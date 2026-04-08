use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};

use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, NSObject, Sel};
use objc2::{ClassType, msg_send, msg_send_id, sel};
use objc2_app_kit::{
    NSApplication, NSImage, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem,
    NSVariableStatusItemLength,
};
use objc2_foundation::{CGFloat, MainThreadMarker, NSInteger, NSSize, NSString};
use uuid::Uuid;

use crate::widgets::format_bytes_per_sec;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub enum MenuAction {
    ShowWindow,
    AddNewVault,
    LockVault(Uuid),
    UnlockVault(Uuid),
    RevealVault(Uuid),
    OpenSettings(Uuid),
    Quit,
}

#[derive(Clone)]
pub struct MenuVaultInfo {
    pub id: Uuid,
    pub name: String,
    pub is_unlocked: bool,
    pub is_busy: bool,
    pub mount_folder: Option<String>,
    pub read_throughput: f64,
    pub write_throughput: f64,
}

#[derive(Clone, Default)]
pub struct MenuBarState {
    pub vaults: Vec<MenuVaultInfo>,
}

pub struct MenuBarHandle {
    pub action_rx: mpsc::Receiver<MenuAction>,
    pub shared_state: Arc<Mutex<MenuBarState>>,
    pub last_synced_generation: u64,
    _status_item: Retained<NSStatusItem>,
}

// ---------------------------------------------------------------------------
// Global statics for ObjC callbacks
// ---------------------------------------------------------------------------

struct MenuBarGlobals {
    action_tx: mpsc::Sender<MenuAction>,
    shared_state: Arc<Mutex<MenuBarState>>,
    /// Maps menu item tag -> (vault_id, action_type).
    /// Populated during `rebuild_menu`, read during `menu_item_clicked_imp`.
    tag_map: Mutex<HashMap<NSInteger, (Uuid, NSInteger)>>,
}

static MENU_GLOBALS: OnceLock<MenuBarGlobals> = OnceLock::new();

/// Stores the delegate pointer as a `usize` so it is naturally `Send + Sync`.
/// SAFETY: The underlying `NSObject` is leaked intentionally and lives for the
/// entire application lifetime. The pointer is only dereferenced on the main
/// thread inside ObjC callbacks and during initial setup.
static DELEGATE_PTR: OnceLock<usize> = OnceLock::new();

// Tag encoding:
//   Special: -1 = ShowWindow, -2 = AddNewVault, -3 = Quit
//   Per-vault: positive tags looked up in `MenuBarGlobals::tag_map`
const TAG_SHOW_WINDOW: NSInteger = -1;
const TAG_ADD_VAULT: NSInteger = -2;
const TAG_QUIT: NSInteger = -3;

const ACTION_LOCK: NSInteger = 0;
const ACTION_UNLOCK: NSInteger = 1;
const ACTION_REVEAL: NSInteger = 2;
const ACTION_SETTINGS: NSInteger = 3;

// ---------------------------------------------------------------------------
// ObjC delegate class (registered manually to avoid declare_class! version issues)
// ---------------------------------------------------------------------------

fn register_delegate_class() -> &'static AnyClass {
    static CLASS: OnceLock<&'static AnyClass> = OnceLock::new();
    CLASS.get_or_init(|| {
        let mut builder = ClassBuilder::new("CryptomatorMenuBarDelegate", NSObject::class())
            .expect("CryptomatorMenuBarDelegate class already registered");

        unsafe {
            builder.add_method(
                sel!(menuNeedsUpdate:),
                menu_needs_update_imp as unsafe extern "C" fn(_, _, _),
            );
            builder.add_method(
                sel!(menuItemClicked:),
                menu_item_clicked_imp as unsafe extern "C" fn(_, _, _),
            );
        }

        builder.register()
    })
}

unsafe extern "C" fn menu_needs_update_imp(_this: &AnyObject, _cmd: Sel, menu: *mut AnyObject) {
    if menu.is_null() {
        return;
    }
    // SAFETY: menu is a valid NSMenu pointer passed by AppKit on the main thread.
    let menu: &NSMenu = unsafe { &*(menu as *const NSMenu) };
    rebuild_menu(menu);
}

unsafe extern "C" fn menu_item_clicked_imp(_this: &AnyObject, _cmd: Sel, sender: *mut AnyObject) {
    if sender.is_null() {
        return;
    }
    let sender: &NSMenuItem = unsafe { &*(sender as *const NSMenuItem) };
    let tag = unsafe { sender.tag() };

    let globals = match MENU_GLOBALS.get() {
        Some(g) => g,
        None => return,
    };

    let action = match tag {
        TAG_SHOW_WINDOW => Some(MenuAction::ShowWindow),
        TAG_ADD_VAULT => Some(MenuAction::AddNewVault),
        TAG_QUIT => Some(MenuAction::Quit),
        _ => {
            let tag_map = match globals.tag_map.lock().ok() {
                Some(m) => m,
                None => return,
            };
            tag_map.get(&tag).and_then(|(vault_id, action_type)| {
                let id = *vault_id;
                match *action_type {
                    ACTION_LOCK => Some(MenuAction::LockVault(id)),
                    ACTION_UNLOCK => Some(MenuAction::UnlockVault(id)),
                    ACTION_REVEAL => Some(MenuAction::RevealVault(id)),
                    ACTION_SETTINGS => Some(MenuAction::OpenSettings(id)),
                    _ => None,
                }
            })
        }
    };

    if let Some(action) = action {
        let _ = globals.action_tx.send(action);
    }
}

// ---------------------------------------------------------------------------
// Menu rebuilding
// ---------------------------------------------------------------------------

/// Allocate the next unique positive tag and insert a mapping for it.
fn alloc_vault_tag(
    next_tag: &mut NSInteger,
    tag_map: &mut HashMap<NSInteger, (Uuid, NSInteger)>,
    vault_id: Uuid,
    action_type: NSInteger,
) -> NSInteger {
    let tag = *next_tag;
    *next_tag += 1;
    tag_map.insert(tag, (vault_id, action_type));
    tag
}

fn rebuild_menu(menu: &NSMenu) {
    let mtm = MainThreadMarker::from(menu);
    let action_sel = sel!(menuItemClicked:);

    unsafe {
        menu.removeAllItems();
    }

    let globals = match MENU_GLOBALS.get() {
        Some(g) => g,
        None => return,
    };
    let state = match globals.shared_state.lock().ok() {
        Some(s) => s,
        None => return,
    };

    // Clear and rebuild the tag map for this menu generation.
    let mut tag_map = match globals.tag_map.lock().ok() {
        Some(m) => m,
        None => return,
    };
    tag_map.clear();
    let mut next_tag: NSInteger = 1;

    let target: Option<&AnyObject> = DELEGATE_PTR
        .get()
        .map(|p| unsafe { &*(*p as *const AnyObject) });

    // "Show Cryptomator"
    add_action_item(
        menu,
        mtm,
        "Show Cryptomator",
        action_sel,
        TAG_SHOW_WINDOW,
        target,
    );
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    // Unlocked vaults
    let unlocked: Vec<_> = state.vaults.iter().filter(|v| v.is_unlocked).collect();

    if !unlocked.is_empty() {
        add_section_header(menu, mtm, "UNLOCKED");
        for vault in &unlocked {
            let stats = format!(
                "{}  \u{2B07}{} \u{2B06}{}",
                vault.name,
                format_bytes_per_sec(vault.read_throughput),
                format_bytes_per_sec(vault.write_throughput),
            );
            add_disabled_item(menu, mtm, &stats);

            let lock_tag = alloc_vault_tag(&mut next_tag, &mut tag_map, vault.id, ACTION_LOCK);
            add_action_item(menu, mtm, "    Lock", action_sel, lock_tag, target);
            if vault.mount_folder.is_some() {
                let reveal_tag =
                    alloc_vault_tag(&mut next_tag, &mut tag_map, vault.id, ACTION_REVEAL);
                add_action_item(
                    menu,
                    mtm,
                    "    Reveal in Finder",
                    action_sel,
                    reveal_tag,
                    target,
                );
            }
        }
        menu.addItem(&NSMenuItem::separatorItem(mtm));
    }

    // Locked vaults
    let locked: Vec<_> = state
        .vaults
        .iter()
        .filter(|v| !v.is_unlocked && !v.is_busy)
        .collect();

    if !locked.is_empty() {
        add_section_header(menu, mtm, "LOCKED");
        for vault in &locked {
            add_disabled_item(menu, mtm, &vault.name);
            let unlock_tag = alloc_vault_tag(&mut next_tag, &mut tag_map, vault.id, ACTION_UNLOCK);
            add_action_item(
                menu,
                mtm,
                "    Unlock\u{2026}",
                action_sel,
                unlock_tag,
                target,
            );
            let settings_tag =
                alloc_vault_tag(&mut next_tag, &mut tag_map, vault.id, ACTION_SETTINGS);
            add_action_item(menu, mtm, "    Settings", action_sel, settings_tag, target);
        }
        menu.addItem(&NSMenuItem::separatorItem(mtm));
    }

    // Busy vaults (unlocking/locking)
    let busy: Vec<_> = state.vaults.iter().filter(|v| v.is_busy).collect();

    if !busy.is_empty() {
        for vault in &busy {
            let label = format!("{} \u{23F3}", vault.name);
            add_disabled_item(menu, mtm, &label);
        }
        menu.addItem(&NSMenuItem::separatorItem(mtm));
    }

    // "Add New Vault..."
    add_action_item(
        menu,
        mtm,
        "Add New Vault\u{2026}",
        action_sel,
        TAG_ADD_VAULT,
        target,
    );
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    // "Quit Cryptomator"
    add_action_item(menu, mtm, "Quit Cryptomator", action_sel, TAG_QUIT, target);
}

fn add_action_item(
    menu: &NSMenu,
    mtm: MainThreadMarker,
    title: &str,
    action: Sel,
    tag: NSInteger,
    target: Option<&AnyObject>,
) {
    let ns_title = NSString::from_str(title);
    let empty_key = NSString::from_str("");
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            &ns_title,
            Some(action),
            &empty_key,
        )
    };
    unsafe {
        item.setTag(tag);
        item.setTarget(target);
    }
    menu.addItem(&item);
}

fn add_disabled_item(menu: &NSMenu, mtm: MainThreadMarker, title: &str) {
    let ns_title = NSString::from_str(title);
    let empty_key = NSString::from_str("");
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(mtm.alloc(), &ns_title, None, &empty_key)
    };
    unsafe {
        item.setEnabled(false);
    }
    menu.addItem(&item);
}

fn add_section_header(menu: &NSMenu, mtm: MainThreadMarker, title: &str) {
    let ns_title = NSString::from_str(title);
    let header = unsafe { NSMenuItem::sectionHeaderWithTitle(&ns_title, mtm) };
    menu.addItem(&header);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set the macOS dock / application icon to the same SF Symbol used by the
/// menu bar (status item) widget so the app icon and the top-bar widget
/// share a single visual identity.
pub fn set_app_icon() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    let mtm = match MainThreadMarker::new() {
        Some(mtm) => mtm,
        None => {
            DONE.store(false, Ordering::SeqCst);
            return;
        }
    };
    unsafe {
        let symbol_name = NSString::from_str("lock.shield");
        let accessibility = NSString::from_str("Cryptomator");
        let Some(image) = NSImage::imageWithSystemSymbolName_accessibilityDescription(
            &symbol_name,
            Some(&accessibility),
        ) else {
            return;
        };
        // Render full-color (not template) at dock-icon resolution.
        image.setTemplate(false);
        image.setSize(NSSize {
            width: 512.0 as CGFloat,
            height: 512.0 as CGFloat,
        });
        let app = NSApplication::sharedApplication(mtm);
        app.setApplicationIconImage(Some(&image));
    }
}

pub fn setup_menu_bar() -> MenuBarHandle {
    let mtm = MainThreadMarker::new().expect("must be called from the main thread");
    let (action_tx, action_rx) = mpsc::channel();
    let shared_state = Arc::new(Mutex::new(MenuBarState::default()));

    assert!(
        MENU_GLOBALS
            .set(MenuBarGlobals {
                action_tx,
                shared_state: shared_state.clone(),
                tag_map: Mutex::new(HashMap::new()),
            })
            .is_ok(),
        "menu bar already initialized"
    );

    // Register and instantiate the delegate class
    let delegate_class = register_delegate_class();
    let delegate: Retained<NSObject> = unsafe { msg_send_id![delegate_class, new] };

    // SAFETY: `into_raw` consumes the Retained without running the destructor,
    // keeping the delegate alive for the entire application lifetime.
    let delegate_ptr = Retained::into_raw(delegate) as *const AnyObject;

    // Store as usize for Send+Sync safety.
    assert!(
        DELEGATE_PTR.set(delegate_ptr as usize).is_ok(),
        "menu bar already initialized"
    );

    let status_item = unsafe {
        let status_bar = NSStatusBar::systemStatusBar();
        let status_item = status_bar.statusItemWithLength(NSVariableStatusItemLength);

        // Set icon
        if let Some(button) = status_item.button(mtm) {
            let symbol_name = NSString::from_str("lock.shield");
            let accessibility = NSString::from_str("Cryptomator");
            let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(
                &symbol_name,
                Some(&accessibility),
            );
            if let Some(image) = image {
                image.setTemplate(true);
                button.setImage(Some(&image));
            } else {
                let title = NSString::from_str("\u{1F512}");
                button.setTitle(&title);
            }
        }

        // Create menu and set delegate via msg_send (avoids typed NSMenuDelegate protocol)
        let menu = NSMenu::new(mtm);
        // SAFETY: delegate_ptr is valid for the lifetime of the application.
        let delegate_obj: &AnyObject = &*delegate_ptr;
        let _: () = msg_send![&menu, setDelegate: delegate_obj];
        status_item.setMenu(Some(&menu));

        status_item
    };

    MenuBarHandle {
        action_rx,
        shared_state,
        last_synced_generation: 0,
        _status_item: status_item,
    }
}

/// Update the shared menu bar state from current app state.
pub fn update_state(
    handle: &MenuBarHandle,
    vaults: &[crate::storage::VaultEntry],
    runtimes: &std::collections::HashMap<Uuid, crate::vault_runtime::VaultRuntime>,
) {
    let infos: Vec<MenuVaultInfo> = vaults
        .iter()
        .map(|entry| {
            let rt = runtimes.get(&entry.id);
            let status = rt
                .map(|r| r.status)
                .unwrap_or(crate::vault_runtime::VaultStatus::Locked);
            MenuVaultInfo {
                id: entry.id,
                name: entry.name.clone(),
                is_unlocked: status == crate::vault_runtime::VaultStatus::Unlocked,
                is_busy: matches!(
                    status,
                    crate::vault_runtime::VaultStatus::Unlocking
                        | crate::vault_runtime::VaultStatus::Locking
                ),
                mount_folder: rt.and_then(|r| r.active_mount_folder.clone()),
                read_throughput: rt.map(|r| r.read_throughput).unwrap_or(0.0),
                write_throughput: rt.map(|r| r.write_throughput).unwrap_or(0.0),
            }
        })
        .collect();

    if let Ok(mut state) = handle.shared_state.lock() {
        state.vaults = infos;
    }
}
