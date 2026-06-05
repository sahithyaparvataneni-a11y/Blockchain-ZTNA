from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
	       path('UserLogin', views.UserLogin, name="UserLogin"),
	       path('UserLoginAction', views.UserLoginAction, name="UserLoginAction"),	   
	       path('Register', views.Register, name="Register"),
	       path('RegisterAction', views.RegisterAction, name="RegisterAction"),
	       path('UploadFile', views.UploadFile, name="UploadFile"),	
	       path('UploadFileAction', views.UploadFileAction, name="UploadFileAction"),
	       path('AccessData', views.AccessData, name="AccessData"),	
	       path('ViewActivities', views.ViewActivities, name="ViewActivities"),	
	       path('Download', views.Download, name="Download"),
]