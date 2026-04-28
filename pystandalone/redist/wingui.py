from __future__ import annotations

from ctypes import (
    POINTER,
    WINFUNCTYPE,
    Structure,
    WinDLL,
    WinError,
    byref,
    c_int,
    c_int64,
    c_void_p,
    create_string_buffer,
    get_last_error,
    string_at,
)
from ctypes import wintypes as w
from typing import Any


def _winerror(result: int, *args) -> Any:
    if not result:
        raise WinError(get_last_error())
    return result


LRESULT = c_int64
HCURSOR = c_void_p

WNDPROC = WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)


class WNDCLASSW(Structure):
    _fields_ = (
        ("style", w.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", c_int),
        ("cbWndExtra", c_int),
        ("hInstance", w.HINSTANCE),
        ("hIcon", w.HICON),
        ("hCursor", HCURSOR),
        ("hbrBackground", w.HBRUSH),
        ("lpszMenuName", w.LPCWSTR),
        ("lpszClassName", w.LPCWSTR),
    )


class PAINTSTRUCT(Structure):
    _fields_ = (
        ("hdc", w.HDC),
        ("fErase", w.BOOL),
        ("rcPaint", w.RECT),
        ("fRestore", w.BOOL),
        ("fIncUpdate", w.BOOL),
        ("rgbReserved", w.BYTE * 32),
    )


def RECT(top: int, left: int, right: int, bottom: int) -> w.RECT:
    rectangle = w.RECT()
    rectangle.top = top
    rectangle.left = left
    rectangle.right = right
    rectangle.bottom = bottom
    return rectangle


kernel32 = WinDLL("kernel32", use_last_error=True)
kernel32.GetModuleHandleW.argtypes = (w.LPCWSTR,)
kernel32.GetModuleHandleW.restype = w.HMODULE
kernel32.GetModuleHandleW._winerror = _winerror

user32 = WinDLL("user32", use_last_error=True)
user32.CreateWindowExW.argtypes = (
    w.DWORD,
    w.LPCWSTR,
    w.LPCWSTR,
    w.DWORD,
    c_int,
    c_int,
    c_int,
    c_int,
    w.HWND,
    w.HMENU,
    w.HINSTANCE,
    w.LPVOID,
)
user32.CreateWindowExW.restype = w.HWND
user32.CreateWindowExW._winerror = _winerror
user32.LoadIconW.argtypes = w.HINSTANCE, w.LPCWSTR
user32.LoadIconW.restype = w.HICON
user32.LoadIconW._winerror = _winerror
user32.LoadCursorW.argtypes = w.HINSTANCE, w.LPCWSTR
user32.LoadCursorW.restype = HCURSOR
user32.LoadCursorW._winerror = _winerror
user32.RegisterClassW.argtypes = (POINTER(WNDCLASSW),)
user32.RegisterClassW.restype = w.ATOM
user32.RegisterClassW._winerror = _winerror
user32.ShowWindow.argtypes = w.HWND, c_int
user32.ShowWindow.restype = w.BOOL
user32.UpdateWindow.argtypes = (w.HWND,)
user32.UpdateWindow.restype = w.BOOL
user32.UpdateWindow._winerror = _winerror
user32.GetMessageW.argtypes = POINTER(w.MSG), w.HWND, w.UINT, w.UINT
user32.GetMessageW.restype = w.BOOL
user32.TranslateMessage.argtypes = (POINTER(w.MSG),)
user32.TranslateMessage.restype = w.BOOL
user32.DispatchMessageW.argtypes = (POINTER(w.MSG),)
user32.DispatchMessageW.restype = LRESULT
user32.BeginPaint.argtypes = w.HWND, POINTER(PAINTSTRUCT)
user32.BeginPaint.restype = w.HDC
user32.BeginPaint._winerror = _winerror
user32.GetClientRect.argtypes = w.HWND, POINTER(w.RECT)
user32.GetClientRect.restype = w.BOOL
user32.GetClientRect._winerror = _winerror
user32.DrawTextW.argtypes = w.HDC, w.LPCWSTR, c_int, POINTER(w.RECT), w.UINT
user32.DrawTextW.restype = c_int
user32.EndPaint.argtypes = w.HWND, POINTER(PAINTSTRUCT)
user32.EndPaint.restype = w.BOOL
user32.PostQuitMessage.argtypes = (c_int,)
user32.PostQuitMessage.restype = None
user32.DefWindowProcW.argtypes = w.HWND, w.UINT, w.WPARAM, w.LPARAM
user32.DefWindowProcW.restype = LRESULT

gdi32 = WinDLL("gdi32", use_last_error=True)
gdi32.GetStockObject.argtypes = (c_int,)
gdi32.GetStockObject.restype = w.HGDIOBJ

SendMessage = user32.SendMessageA
SendMessage.argtypes = (w.HWND, w.UINT, w.WPARAM, w.LPARAM)
SendMessage.restype = c_void_p

CW_USEDEFAULT = -2147483648
IDI_APPLICATION = w.LPCWSTR(32512)

CS_HREDRAW = 2
CS_VREDRAW = 1

IDC_ARROW = w.LPCWSTR(32512)
WHITE_BRUSH = 0

SW_SHOWNORMAL = 1

WM_DESTROY = 2
WM_PAINT = 15
WM_COMMAND = 273

DT_SINGLELINE = 32
DT_CENTER = 1
DT_VCENTER = 4

WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_BORDER = 0x00800000
WS_OVERLAPPEDWINDOW = 13565952


BS_PUSHBUTTON = 0
BS_CHECKBOX = 2
BS_AUTOCHECKBOX = 3


ES_PASSWORD = 32
ES_WANTRETURN = 4096
EM_SETPASSWORDCHAR = 204


class KeyGUI:
    result = ""
    pass_shown = False
    gui_display_text = ""
    accept_button = None
    input_field = None
    checkbox = None
    reveal_text = None
    label = None

    @classmethod
    def prompt(
        cls: KeyGUI,
        text: str,
        title: str = "Unlock",
        label_text: str = "Key:",
        reveal_text: str = "reveal key",
        button_text: str = "Unlock",
    ) -> str:
        cls.gui_display_text = text
        cls.label = label_text
        cls.reveal_text = reveal_text
        wndclass = WNDCLASSW()
        wndclass.style = CS_HREDRAW | CS_VREDRAW
        wndclass.lpfnWndProc = WNDPROC(_winmessage)
        wndclass.cbClsExtra = wndclass.cbWndExtra = 0
        wndclass.hInstance = kernel32.GetModuleHandleW(None)
        wndclass.hIcon = user32.LoadIconW(None, IDI_APPLICATION)
        wndclass.hCursor = user32.LoadCursorW(None, IDC_ARROW)
        wndclass.hbrBackground = gdi32.GetStockObject(WHITE_BRUSH)
        wndclass.lpszMenuName = None
        wndclass.lpszClassName = "KeyPrompt"
        user32.RegisterClassW(byref(wndclass))
        hwnd = user32.CreateWindowExW(
            0,
            wndclass.lpszClassName,
            title,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            200,
            None,
            None,
            wndclass.hInstance,
            None,
        )
        cls.input_field = user32.CreateWindowExW(
            0,
            "Edit",
            None,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_WANTRETURN,
            60,
            60,
            600,
            32,
            hwnd,
            0,
            0,
            0,
        )
        cls.accept_button = user32.CreateWindowExW(
            0, "Button", button_text, WS_CHILD | WS_VISIBLE | WS_BORDER, 670, 60, 60, 32, hwnd, 0, 0, 0
        )
        cls.checkbox = user32.CreateWindowExW(
            0, "Button", None, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 60, 95, 16, 16, hwnd, 0, 0, 0
        )
        SendMessage(cls.input_field, EM_SETPASSWORDCHAR, w.WPARAM(ord("*")), 0)
        user32.ShowWindow(hwnd, SW_SHOWNORMAL)
        user32.UpdateWindow(hwnd)
        msg = w.MSG()
        while user32.GetMessageW(byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageW(byref(msg))
        return str(cls.result)


def _winmessage(hwnd: w.HWND, message: w.UINT, wParam: w.WPARAM, lParam: w.LPARAM) -> w.LRESULT:
    ps = PAINTSTRUCT()
    rect = w.RECT()
    if message == WM_COMMAND:
        if lParam == KeyGUI.accept_button:
            buf = create_string_buffer(b"", size=1000)
            user32.GetWindowTextA(KeyGUI.input_field, byref(buf), 1000)
            user32.PostQuitMessage(0)
            KeyGUI.result = string_at(buf).decode("ascii")

        if lParam == KeyGUI.checkbox:
            if not KeyGUI.pass_shown:
                SendMessage(KeyGUI.input_field, EM_SETPASSWORDCHAR, 0, 0)
                KeyGUI.pass_shown = True
            else:
                SendMessage(KeyGUI.input_field, EM_SETPASSWORDCHAR, w.WPARAM(ord("*")), 0)
                KeyGUI.pass_shown = False

            user32.InvalidateRect(hwnd, 0, 0)

        return 0

    if message == WM_PAINT:
        hdc = user32.BeginPaint(hwnd, byref(ps))
        user32.GetClientRect(hwnd, byref(rect))
        user32.DrawTextW(hdc, KeyGUI.gui_display_text, c_int(-1), byref(RECT(10, 10, 590, 40)), DT_SINGLELINE)
        user32.DrawTextW(hdc, KeyGUI.label, c_int(-1), byref(RECT(60, 10, 200, 140)), DT_SINGLELINE)
        user32.DrawTextW(hdc, KeyGUI.reveal_text, c_int(-1), byref(RECT(95, 80, 200, 140)), DT_SINGLELINE)
        user32.EndPaint(hwnd, byref(ps))
        user32.EndPaint(hwnd, byref(ps))
        return 0
    if message == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0

    return user32.DefWindowProcW(hwnd, message, wParam, lParam)
