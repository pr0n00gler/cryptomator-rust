use crate::cryptofs::error::FileSystemError::{InvalidPathError, PathIsNotExist, UnknownError};
use crate::cryptofs::FileSystemError;
use std::path::{Component, Path};

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
/// println!("{}", last_component); // "d"
/// ```
pub fn last_path_component<S: AsRef<Path>>(path: S) -> Result<String, FileSystemError> {
    let components = std::path::Path::new(path.as_ref())
        .components()
        .collect::<Vec<std::path::Component>>();
    Ok(match components.last() {
        Some(c) => match c.as_os_str().to_str() {
            Some(s) => String::from(s),
            None => return Err(UnknownError(String::from("failed to convert OsStr to str"))),
        },
        None => {
            return Err(PathIsNotExist(format!(
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
/// println!("{}", parent); // "/a/b/c"
/// ```
pub fn parent_path<S: AsRef<Path>>(path: S) -> String {
    let components = std::path::Path::new(path.as_ref())
        .components()
        .collect::<Vec<std::path::Component>>();
    let mut dir_path = std::path::PathBuf::new(); //path without filename
    for (i, c) in components.iter().enumerate() {
        if i > components.len() - 2 {
            break;
        }
        dir_path = dir_path.join(c.as_ref() as &Path);
    }
    match dir_path.to_str() {
        Some(s) => String::from(s),
        None => String::new(),
    }
}
