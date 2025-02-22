from soft_webauthn_patched import SoftWebauthnDevice


def test_patch():
    """Asserts bit flags are patched as expected."""
    assert b"\x45" in SoftWebauthnDevice.create.__code__.co_consts
    assert b"\x05" in SoftWebauthnDevice.get.__code__.co_consts
