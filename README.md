# Item Catalog Project - FSND Project 4

This is the source code for the Item Catalog Project, the fourth project of Full Stack Nanodegree Programme in Udacity. This project is developed by Widya A. Puspitaloka.

Coldplay Discography App provides a list of songs within a variety of albums as well as provide a user registration and authentication system. This is a python module that creates a website and JSON API for a list of albums. Registered users will have the ability to post, edit and delete their own items. While unregistered user can only access public page.
 
This application uses Flask,SQL Alchemy, JQuery,CSS, Javascript, and OAuth2.

### Tools
1. Python 2.7
2. [Vagrant](https://www.vagrantup.com/downloads.html)
3. [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
4. OAuth 2.0
5. Flask
6. SQLAlchemy

### Setup
* Download and isntall Python 2 (if you have not already)
* Download and install [vagrant](https://www.vagrantup.com/downloads.html) (the link is provided by Udacity)
* Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (the link is provided by Udacity)
* Clone or download, then unzip VM configuration, [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm ) provided by Udacity
* Clone or download this repository into `vagrant` directory

### Usage
Starting virtual machine 
* From your terminal, go to a new directory containing the VM files
* Inside, you will find another directory called `vagrant`. Change directory to the `vagrant` directory
* Inside the vagrant subdirectory, run the command `vagrant up` to download the Linux operating system and install it
* Then, to log in to the installed Linux VM, run `vagrant ssh`
* Inside the VM, change directory to `/vagrant` and look around with `ls` command.

Set up a Google authorization application
* Go to https://console.developers.google.com/project and login with Google.
* Create a new project
* Name the project
* Choose Credentials from the menu on the left.
* Create an OAuth Client ID.
* Configure the consent screen
* Click create client ID
* In Authorized javascript origins add://localhost:5000
* Click download JSON and save it into the same directory as  this project.
* Rename the JSON file "client_secrets.json"
* In main.html replace the line "data-clientid="xxxx" so that it uses your Client ID from the web applciation.

Loading the data
* Unzip the cloned repo, place the folder in the same directory as the `VagrantFile` file inside `vagrant`.
* From your terminal, go to a new directory containing the cloned repository
* Run `python database_setup.py` to create the database.
* Run `python coldplaydiscography.py` to add the song and album items

Running the script
* Inside the `vagrant` directory in the VM, go to a new directory containing the cloned repository
* Run `$ python finalproject.py` to execute the program and to look at the database
* Open your webbrowser and visit http://localhost:5000/

### Expected Functionality
* Without logged in, users only can see public pages
* Users can login / logout with Google account.
* Logged in users can add, edit and delete their own album and song.
* Can access JSON data 

### License
This project is released under the [MIT License](https://opensource.org/licenses/MIT)
