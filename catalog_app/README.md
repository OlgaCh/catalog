# Kid's Places Catalog App

## Project Goal
To show places which are typically hidden in the city.
They can't be discovered while looking at the Google or Yandex 
(Russian local tool) maps. As well as by Googling without knowing exact place 
name.

In order to limit the scope of places only places for Kids will be considered.

## Data Source
Social networks could be used as a data-providers for this service.
Data may be obtained from `facebook`, `vk.com`, `instagram.com`, etc.

`Disclaimer`: originally I was up to create automatic crawler for those data 
sources. But then realize that it could be too time consuming considering the
timeline of this project. Currently database is populated by data entered 
manually.

## Running the app

If you like to run it on your local machine please follow instructions below.

1. You should have Python 3.5+ and `pip` installed.

2. In terminal execute `pip install -r requirements.txt`

3. Start application with `python app.py`

4. Application will be up and running at `http://localhost:5000/`.

Please make sure to not change the port! It is used for security reason and 
linked to Google auth. From different port you won't be able to login to the 
application.


### N.B! 
Database is already initialized and has some data pre-populated.
In the case if you like to reset it's state please run in the shell

`python models.py`