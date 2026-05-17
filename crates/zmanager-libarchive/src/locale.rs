#[cfg(unix)]
pub(crate) struct Utf8LocaleGuard {
    previous: libc::locale_t,
    current: libc::locale_t,
}

#[cfg(unix)]
impl Utf8LocaleGuard {
    pub(crate) fn new() -> Self {
        #[cfg(any(target_os = "linux", target_os = "illumos"))]
        let locale_name = c"";

        #[cfg(target_os = "macos")]
        let locale_name = c"UTF-8";

        #[cfg(not(any(target_os = "linux", target_os = "illumos", target_os = "macos")))]
        let locale_name = c"";

        let current = unsafe {
            libc::newlocale(
                libc::LC_CTYPE_MASK,
                locale_name.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        let previous = if current.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe { libc::uselocale(current) }
        };

        Self { previous, current }
    }
}

#[cfg(unix)]
impl Drop for Utf8LocaleGuard {
    fn drop(&mut self) {
        if self.current.is_null() {
            return;
        }
        unsafe {
            libc::uselocale(self.previous);
            libc::freelocale(self.current);
        }
    }
}

#[cfg(not(unix))]
pub(crate) struct Utf8LocaleGuard;

#[cfg(not(unix))]
impl Utf8LocaleGuard {
    pub(crate) fn new() -> Self {
        Self
    }
}
