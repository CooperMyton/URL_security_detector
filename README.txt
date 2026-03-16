URL Security Defender
By: Simon Casey and Cooper Myton

About This Project:
URL Security Defender is a Python Project created to take in input URL's from a user and output vulnerability results based on scans on that URL using URLLib.

Setup instructions:
1) Open a terminal window, through vscode or otherwise.

2) Install the required libraries using the command "pip install -r requirements.txt" (creating a venv is recommended, but not required).


Usage instructions
1) Navigate to [project_root]/django_front_end

2) execute the command "python manage.py runserver" 

3) open a browser and navigate to http://127.0.0.1:800/

4) you should now have access to the active website. Enter any URL you like to test it, and navigate around the website as you please. Our list of testing URL's can be found in the test_links.txt file.

Files of note(while all parts of the codebase are necessary for the checker to function, these are the locations with the most relevant logic):
-django_front_end/mainPage/templates/test_template.html
-django_front_end/resourcesPage/templates/resources_mainpage.html
-django_front_end/mainPage/views.py
-django_front_end/resourcesPage/views.py
-django_front_end/mainPage/forms.py
-django_front_end/mainPage/resources/malicious_domains_polska_3-8-2026.txt
-test_links.txt
-requirements.txt