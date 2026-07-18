from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.accounts.forms import CustomUserChangeForm

User = get_user_model()


class CustomUserChangeFormTest(TestCase):
    def test_empty_username_validation_passes(self):
        """
        Verify that validating a form with an empty username does not raise a TypeError.
        """
        # Create a user with a None username
        user = User.objects.create(email="testuser@example.com", username=None)

        # Verify that CustomUserChangeForm processes the empty/None username correctly
        form = CustomUserChangeForm(
            instance=user,
            data={
                "email": "testuser@example.com",
                "username": "",  # Empty string from form POST
                "failed_login_attempts": 0,
                "password_changed_at": user.password_changed_at,
            }
        )

        # The form should validate without raising any TypeError
        try:
            is_valid = form.is_valid()
        except TypeError as e:
            self.fail(f"Form validation raised TypeError: {e}")

        # Check that it cleaned username to None
        if is_valid:
            self.assertIsNone(form.cleaned_data["username"])
