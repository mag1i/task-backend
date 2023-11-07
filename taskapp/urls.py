from django.urls import include, path

from taskapp import views
from taskapp.views import UserLoginView, UserSignupView, UserView, LogoutView, UserRetrieveView, \
    PasswordResetRequestView

urlpatterns = [
    path('signup/', UserSignupView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('user', UserRetrieveView.as_view(), name='user'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('forgotpw', PasswordResetRequestView.as_view(), name='forgotpw'),

]