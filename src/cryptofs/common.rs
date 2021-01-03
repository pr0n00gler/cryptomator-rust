use crate::cryptofs::error::FileSystemError::{InvalidPathError, PathIsNotExist, UnknownError};
use crate::cryptofs::FileSystemError;
use std::path::{Component, Path};

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

pub fn last_path_component(path: &str) -> Result<String, FileSystemError> {
    let components = std::path::Path::new(path)
        .components()
        .collect::<Vec<std::path::Component>>();
    Ok(match components.last() {
        Some(c) => match c.as_os_str().to_str() {
            Some(s) => String::from(s),
            None => return Err(UnknownError(String::from("failed to convert OsStr to str"))),
        },
        None => return Err(PathIsNotExist(format!("invalid path: {}", path))),
    })
}

pub fn parent_path(path: &str) -> String {
    let components = std::path::Path::new(path)
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
