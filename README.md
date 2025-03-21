﻿# VidExchange - Video Sharing Platform (Sept 2024)

VidExchange is a full-stack web application designed for secure video uploads, sharing, and management. The platform offers customizable privacy settings, allowing users to manage who can view their videos. Built using Flask (Python), SQLite, and Bootstrap, VidExchange provides a responsive and intuitive user experience.

## Features
- **Secure Video Uploads**: Users can upload videos securely with customizable privacy settings.
- **Video Sharing**: Videos can be shared with other users or kept private, with specific privacy options.
- **User Authentication**: Registration and login features to manage user profiles.
- **Responsive Design**: The platform is designed using Bootstrap to ensure a smooth experience on all devices.
- **Video Management**: Users can view, delete, and manage their uploaded videos.

## Technologies Used
- **Backend**: Python, Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, Bootstrap
- **Video Uploads**: Local file storage for uploaded videos

## File Structure
The project contains the following structure:

    VidExchange/ 
    ├── static/ 
    │   └── styles.css # Custom styles for the platform 
    ├── templates/ 
    │ ├── base.html # Base template with common layout 
    │ ├── error_page.html # Error page template 
    │ ├── index.html # Homepage template 
    │ ├── login.html # Login page template 
    │ ├── myvideos.html # User's uploaded videos page 
    │ ├── play_video.html # Video playback page 
    │ ├── profile.html # User profile page 
    │ └── register.html # Registration page template 
    ├── uploads/ # Folder to store uploaded videos
    ├── app.py # Main Flask application 
    ├── helpers.py # Helper functions for user authentication 
    ├── requirements.txt # Python dependencies 
    └── README.md # Project documentation

## Installation

1. Clone the repository:

    ```git
    git clone https://github.com/Kuldeep7k/VidExchange_-_Video-Sharing-Platform
    
    cd VidExchange
    ```
2. Set up a virtual environment:
    ```cmd
   python3 -m venv venv
   
   source venv/bin/activate   
   
   # On Windows: venv\Scripts\activate
    ```
3. Install dependencies:

    ```python
   pip install -r requirements.txt
    ```
4. Run the application:
    ```python
   python app.py
    ```

5. Open a browser and navigate to http://127.0.0.1:5000/ to access VidExchange.

## Requirements
- Python 3.x
- Flask
- SQLite (No setup needed as SQLite is a lightweight, file-based database)
- Other dependencies (listed in requirements.txt)

## Usage

- Register: Users can create a new account by navigating to the registration page.
- Login: Existing users can log in to access their profile and uploaded videos.
- Upload Videos: Users can upload videos from their local device with privacy options.
- Manage Videos: Users can view, delete, and manage their uploaded videos.
- Profile: Users can view and edit their profile information.

## Customization

- To modify the style of the platform, you can edit the static/styles.css file.
- The templates in templates/ are customizable to change the look and feel of the web pages.
- You can modify the privacy settings and video management functionality in helpers.py and app.py.

## License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/Kuldeep7k/VidExchange_-_Video-Sharing-Platform/blob/main/LICENSE) file for details.

