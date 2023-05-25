// SPDX-License-Identifier: MIT OR Apache-2.0 OR Zlib

// Copyright 2023 John Nunley
//
// Licensed under the Apache License, Version 2.0, the MIT License, and
// the Zlib license. You may not use this software except in compliance
// with at least one of these licenses. You should have received a copy
// of these licenses with this software. You may also find them at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//     https://opensource.org/licenses/MIT
//     https://opensource.org/licenses/Zlib
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the licenses for the specific language governing permissions and
// limitations under the licenses.

//! A tiny set of bindings to the [Xlib] library.

mod ffi;

use std::cell::Cell;
use std::ffi::CStr;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::raw::{c_int, c_void};
use std::ptr::{self, NonNull};
use std::sync::{Mutex, Once};

/// The global bindings to Xlib.
#[ctor::ctor]
static XLIB: io::Result<ffi::Xlib> = {
    unsafe fn load_xlib_with_error_hook() -> io::Result<ffi::Xlib> {
        // Here's a puzzle: how do you *safely* add an error hook to Xlib? Like signal handling, there
        // is a single global error hook. Therefore, we need to make sure that we economize on the
        // single slot that we have by offering a way to set it. However, unlike signal handling, there
        // is no way to tell if we're replacing an existing error hook. If we replace another library's
        // error hook, we could cause unsound behavior if it assumes that it is the only error hook.
        //
        // However, we don't want to call the default error hook, because it exits the program. So, in
        // order to tell if the error hook is the default one, we need to compare it to the default
        // error hook. However, we can't just compare the function pointers, because the default error
        // hook is a private function that we can't access.
        //
        // In order to access it, before anything else runs, this function is called. It loads Xlib,
        // sets the error hook to a dummy function, reads the resulting error hook into a static
        // variable, and then resets the error hook to the default function. This allows us to read
        // the default error hook and compare it to the one that we're setting.
        let xlib = ffi::Xlib::load().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("failed to load Xlib: {}", e))
        })?;

        // Dummy function we use to set the error hook.
        unsafe extern "C" fn dummy(
            _display: *mut ffi::Display,
            _error: *mut ffi::XErrorEvent,
        ) -> std::os::raw::c_int {
            0
        }

        // Set the error hook to the dummy function.
        let default_hook = xlib.set_error_handler(Some(dummy));

        // Read the error hook into a static variable.
        // SAFETY: This should only run once at the start of the program, no need to worry about
        // multithreading.
        DEFAULT_ERROR_HOOK.set(default_hook);

        // Set the error hook back to the default function.
        xlib.set_error_handler(default_hook);

        Ok(xlib)
    }

    unsafe { load_xlib_with_error_hook() }
};

#[inline]
fn get_xlib(sym: &io::Result<ffi::Xlib>) -> io::Result<&ffi::Xlib> {
    sym.as_ref().map_err(|e| io::Error::from(e.kind()))
}

/// The default error hook to compare against.
static DEFAULT_ERROR_HOOK: ErrorHookSlot = ErrorHookSlot::new();

/// An error handling hook.
type ErrorHook = Box<dyn FnMut(&Display, &ErrorEvent) -> bool + Send + Sync + 'static>;

/// List of error hooks to invoke.
static ERROR_HANDLERS: Mutex<HandlerList> = Mutex::new(HandlerList::new());

unsafe extern "C" fn error_handler(
    display: *mut ffi::Display,
    error: *mut ffi::XErrorEvent,
) -> c_int {
    // Abort the program if the error hook panics.
    struct AbortOnPanic;
    impl Drop for AbortOnPanic {
        fn drop(&mut self) {
            std::process::abort();
        }
    }

    let bomb = AbortOnPanic;

    // Run the previous error hook, if any.
    let mut handlers = ERROR_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
    handlers.run_prev(display, error);

    // Read out the variables.
    let display = mem::ManuallyDrop::new(Display {
        ptr: NonNull::new_unchecked(display),
        _marker: PhantomData,
    });
    let event = ErrorEvent(ptr::read(error));

    // Invoke the error hooks.
    handlers
        .iter_mut()
        .any(|handler| (handler)(&display, &event));

    // Defuse the bomb.
    mem::forget(bomb);

    // Apparently the return value here has no effect.
    0
}

/// Register the error handler.
fn setup_error_handler(xlib: &ffi::Xlib) {
    static REGISTERED: Once = Once::new();
    REGISTERED.call_once(move || {
        // Get the previous error handler.
        let prev = unsafe { xlib.set_error_handler(Some(error_handler)) };

        // If it isn't the default error handler, then we need to store it.
        // SAFETY: DEFAULT_ERROR_HOOK is not set after the program starts, so this is safe.
        let default_hook = unsafe { DEFAULT_ERROR_HOOK.get() };
        if prev != default_hook.flatten() {
            ERROR_HANDLERS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .prev = prev;
        }
    });
}

/// A key to the error handler list that can be used to remove handlers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandlerKey(usize);

/// The error event type.
#[derive(Clone)]
pub struct ErrorEvent(ffi::XErrorEvent);

impl ErrorEvent {
    /// Get the serial number of the failed request.
    #[allow(clippy::unnecessary_cast)]
    pub fn serial(&self) -> u64 {
        self.0.serial as u64
    }

    /// Get the error code.
    pub fn error_code(&self) -> u8 {
        self.0.error_code
    }

    /// Get the request code.
    pub fn request_code(&self) -> u8 {
        self.0.request_code
    }

    /// Get the minor opcode of the failed request.
    pub fn minor_code(&self) -> u8 {
        self.0.minor_code
    }

    /// Get the resource ID of the failed request.
    pub fn resource_id(&self) -> usize {
        self.0.resourceid as usize
    }
}

/// The display pointer.
pub struct Display {
    /// The display pointer.
    ptr: NonNull<ffi::Display>,

    /// This owns the memory that the display pointer points to.
    _marker: PhantomData<Box<ffi::Display>>,
}

impl Display {
    /// Open a new display.
    pub fn new(name: Option<&CStr>) -> io::Result<Self> {
        let xlib = get_xlib(&XLIB)?;
        let name = name.map_or(std::ptr::null(), |n| n.as_ptr());
        let pointer = unsafe { xlib.open_display(name) };

        // Make sure the error handler is registered.
        setup_error_handler(xlib);

        NonNull::new(pointer)
            .map(|ptr| Self {
                ptr,
                _marker: PhantomData,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to open display"))
    }

    /// Get the pointer to the display.
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr().cast()
    }
}

unsafe impl as_raw_xcb_connection::AsRawXcbConnection for Display {
    fn as_raw_xcb_connection(&self) -> *mut as_raw_xcb_connection::xcb_connection_t {
        let xlib = get_xlib(&XLIB).expect("failed to load Xlib");
        unsafe { xlib.get_xcb_connection(self.ptr.as_ptr()) }
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        // SAFETY: We own the display pointer, so we can drop it.
        if let Ok(xlib) = get_xlib(&XLIB) {
            unsafe {
                xlib.close_display(self.ptr.as_ptr());
            }
        }
    }
}

/// Insert an error handler into the list.
pub fn register_error_handler(handler: ErrorHook) -> io::Result<HandlerKey> {
    // Make sure the error handler is registered.
    setup_error_handler(get_xlib(&XLIB)?);

    // Insert the handler into the list.
    let mut handlers = ERROR_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
    let key = handlers.insert(handler);
    Ok(HandlerKey(key))
}

/// Remove an error handler from the list.
pub fn unregister_error_handler(key: HandlerKey) {
    // Remove the handler from the list.
    let mut handlers = ERROR_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
    handlers.remove(key.0);
}

/// The list of error handlers.
struct HandlerList {
    /// The inner list of slots.
    slots: Vec<Slot>,

    /// The number of filled slots.
    filled: usize,

    /// The first unfilled slot.
    unfilled: usize,

    /// The last error handler hook.
    prev: ffi::XErrorHook,
}

/// A slot in the error handler list.
enum Slot {
    /// A slot that is filled.
    Filled(ErrorHook),

    /// A slot that is unfilled.
    ///
    /// This value points to the next unfilled slot.
    Unfilled(usize),
}

impl HandlerList {
    /// Create a new handler list.
    const fn new() -> Self {
        Self {
            slots: vec![],
            filled: 0,
            unfilled: 0,
            prev: None,
        }
    }

    /// Run the previous error handler.
    unsafe fn run_prev(&mut self, display: *mut ffi::Display, event: *mut ffi::XErrorEvent) {
        if let Some(prev) = self.prev {
            prev(display, event);
        }
    }

    /// Push a new error handler.
    ///
    /// Returns the index of the handler.
    fn insert(&mut self, handler: ErrorHook) -> usize {
        let index = self.filled;

        if self.unfilled < self.slots.len() {
            let unfilled = self.unfilled;
            self.unfilled = match self.slots[unfilled] {
                Slot::Unfilled(next) => next,
                _ => unreachable!(),
            };
            self.slots[unfilled] = Slot::Filled(handler);
        } else {
            self.slots.push(Slot::Filled(handler));
        }

        self.filled += 1;

        index
    }

    /// Remove an error handler.
    fn remove(&mut self, index: usize) {
        let slot = &mut self.slots[index];

        if let Slot::Filled(_) = slot {
            *slot = Slot::Unfilled(self.unfilled);
            self.unfilled = index;
            self.filled -= 1;
        }
    }

    /// Iterate over the error handlers.
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut ErrorHook> {
        self.slots.iter_mut().filter_map(|slot| match slot {
            Slot::Filled(handler) => Some(handler),
            _ => None,
        })
    }
}

/// Static unsafe error hook slot.
struct ErrorHookSlot(Cell<Option<ffi::XErrorHook>>);

unsafe impl Sync for ErrorHookSlot {}

impl ErrorHookSlot {
    const fn new() -> Self {
        Self(Cell::new(None))
    }

    unsafe fn get(&self) -> Option<ffi::XErrorHook> {
        self.0.get()
    }

    unsafe fn set(&self, hook: ffi::XErrorHook) {
        self.0.set(Some(hook));
    }
}
