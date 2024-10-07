from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # path('', views.index, name='index'),
    # path('mail/', views.simple, name='simple'),
    # path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    # path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    # path('password_reset_confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('password_reset_complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),

    path('', views.login_view, name='login_view'),
    path('register/', views.register, name='register'),
    # path('logout/', auth_views.LogoutView.as_view(next_page='login_view'), name='logout'),
    path('logout/', views.custom_logout, name='logout'),
  

    path('homepage/', views.homepage, name='homepage'),
    path('delete_course/<int:course_id>/', views.delete_course, name='delete_course'),
    path('add_course/', views.add_course, name='add_course'),
    path('add_pub/', views.add_pub, name='add_pub'),
    path('delete_pub/<int:pub_id>/', views.delete_pub, name='delete_pub'),

    path('timetable/', views.timetable, name='timetable'),

    path('important_documents/', views.important_documents, name='important_documents'),
    path('view_document/<int:document_id>/', views.view_document, name='view_document'),
    path('delete_document/<int:document_id>/', views.delete_document, name='delete_document'),
    
] 

