from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from .views import RegisterAPIView,UserManagementView,UserListView,QuizCreateView,QuizTakingView,QuizResultView,QuizListingView,QuizFilterView,QuizAnalyticsView,UserProfileView


urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('token/', TokenObtainPairView.as_view(), name='token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('users/', UserListView.as_view(), name='userlist'),
    path('users/<int:pk>/', UserManagementView.as_view(), name='usermanagement'),
    path('quiz/create/', QuizCreateView.as_view(), name='quizcreate'),
    path('quiz/<int:pk>/', QuizTakingView.as_view(), name='quiztaking'),
    path('quiz/result/', QuizResultView.as_view(), name='quizresult'),
    path('quiz/list/', QuizListingView.as_view(), name='quizlist'),
    path('quiz/filter/', QuizFilterView.as_view(), name='quizfilter'),
    path('quiz/analytics/', QuizAnalyticsView.as_view(), name='quizanalytics'),

]