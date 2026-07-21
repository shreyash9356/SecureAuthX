"""
Utilities for the user_sessions module.
"""


def parse_user_agent(user_agent_string: str) -> tuple[str, str, str]:
    """
    Parse a User-Agent string to extract (device_type, browser, operating_system).

    Matches model constraints in UserSession.DeviceType.

    Args:
        user_agent_string: Raw User-Agent string from headers.

    Returns:
        tuple: (device_type, browser, operating_system) where device_type
               is one of "DESKTOP", "MOBILE", "TABLET", "UNKNOWN".
    """
    if not user_agent_string:
        return "UNKNOWN", "Unknown Browser", "Unknown OS"

    ua = user_agent_string.lower()

    # Determine device type
    if "ipad" in ua or "tablet" in ua:
        device_type = "TABLET"
    elif "mobile" in ua or "android" in ua or "iphone" in ua:
        device_type = "MOBILE"
    # standard desktop patterns
    elif "windows" in ua or "macintosh" in ua or "linux" in ua:
        device_type = "DESKTOP"
    else:
        device_type = "UNKNOWN"

    # Determine browser
    if "chrome" in ua or "crios" in ua:
        browser = "Chrome"
    elif "firefox" in ua or "fxios" in ua:
        browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua and "chromium" not in ua:
        browser = "Safari"
    elif "edge" in ua or "edg" in ua:
        browser = "Edge"
    elif "opera" in ua or "opr" in ua:
        browser = "Opera"
    else:
        browser = "Unknown Browser"

    # Determine operating system
    if "windows" in ua:
        operating_system = "Windows"
    elif "macintosh" in ua or "mac os x" in ua:
        operating_system = "macOS"
    elif "iphone" in ua or "ipod" in ua:
        operating_system = "iOS"
    elif "ipad" in ua:
        operating_system = "iOS (iPad)"
    elif "android" in ua:
        operating_system = "Android"
    elif "linux" in ua:
        operating_system = "Linux"
    else:
        operating_system = "Unknown OS"

    return device_type, browser, operating_system
