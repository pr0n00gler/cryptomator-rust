use crate::cryptofs::error::FileSystemError::{InvalidPathError, PathDoesNotExist, UnknownError};
use crate::cryptofs::FileSystemError;
use std::path::{Component, Path, PathBuf};

/// Returns a String implementation of a Component
pub fn component_to_string(c: Component) -> Result<String, FileSystemError> {
    match c {
        std::path::Component::RootDir => match c.as_os_str().to_str() {
            Some(s) => Ok(String::from(s)),
            None => Err(UnknownError(String::from("failed to convert OsStr to str"))),
        },
        std::path::Component::Normal(os) => match os.to_str() {
            Some(s) => Ok(String::from(s)),
            None => Err(UnknownError(String::from("failed to convert OsStr to str"))),
        },
        _ => Err(InvalidPathError(String::from(
            c.as_os_str().to_str().unwrap_or_default(),
        ))),
    }
}

/// Returns the last component of a path
/// ```
/// use cryptomator::cryptofs::last_path_component;
/// let last_component = last_path_component("/a/b/c/d").unwrap();
/// assert_eq!("d", last_component.to_str().unwrap_or_default());
/// ```
pub fn last_path_component<S: AsRef<Path>>(path: S) -> Result<PathBuf, FileSystemError> {
    let components = std::path::Path::new(path.as_ref())
        .components()
        .collect::<Vec<std::path::Component>>();
    Ok(match components.last() {
        Some(c) => PathBuf::new().join(c),
        None => {
            return Err(PathDoesNotExist(format!(
                "invalid path: {}",
                path.as_ref().display()
            )))
        }
    })
}

/// Returns a parent of a path
/// The opposite of the 'last_path_component'
/// ```
/// use cryptomator::cryptofs::parent_path;
/// let parent = parent_path("/a/b/c/d");
/// #[cfg(unix)]
/// assert_eq!("/a/b/c", parent.to_str().unwrap_or_default());
/// #[cfg(windows)]
/// assert_eq!("\\a\\b\\c", parent.to_str().unwrap_or_default());
/// ```
pub fn parent_path<S: AsRef<Path>>(path: S) -> PathBuf {
    let components = std::path::Path::new(path.as_ref())
        .components()
        .collect::<Vec<std::path::Component>>();
    let mut dir_path = std::path::PathBuf::new(); //path without filename

    // return the same path if there are no parents
    if components.len() < 2 {
        dir_path.push(path);
        return dir_path;
    }
    for (i, c) in components.iter().enumerate() {
        if i > components.len() - 2 {
            break;
        }
        dir_path = dir_path.join(c.as_ref() as &Path);
    }
    dir_path
}
