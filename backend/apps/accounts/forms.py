from django.contrib.auth.forms import UserCreationForm, UserChangeForm, UsernameField

from .models import User


class SafeUsernameField(UsernameField):
    """
    Subclass of UsernameField that safely handles empty/null values when
    the user model's username field has null=True.
    """
    def to_python(self, value):
        if value in self.empty_values:
            return self.empty_value
        return super().to_python(value)


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("email",)
        field_classes = {"username": SafeUsernameField}


class CustomUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        fields = "__all__"
        field_classes = {"username": SafeUsernameField}