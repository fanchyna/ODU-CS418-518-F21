<!DOCTYPE html>
<html lang="{{ app()->getLocale() }}">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- CSRF Token -->
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ config('app.name', 'Articles Index') }}</title>

    <!-- Styles -->
    <link href="{{ mix('css/app.css') }}" rel="stylesheet">

    <style>
    * {
    box-sizing: border-box;
    }

    .row {
    display: flex;
    }

    /* Create two equal columns that sits next to each other */
    .column {
    flex: 50%;
    padding: 10px;
    height: 300px; /* Should be removed. Only for demonstration */
    }

    body {font-family: Arial;color:black}

    /* Style the tab */
    .tab {
    overflow: hidden;
    border: 1px solid #ccc;
    background-color: #f1f1f1;
    }

    /* Style the buttons inside the tab */
    .tab button {
    background-color: inherit;
    float: left;
    border: none;
    outline: none;
    cursor: pointer;
    padding: 14px 16px;
    transition: 0.3s;
    font-size: 17px;
    color: black;
    }

    /* Change background color of buttons on hover */
    .tab button:hover {
    background-color: #ddd;
    }

    /* Create an active/current tablink class */
    .tab button.active {
    background-color: #ccc;
    }

    /* Style the tab content */
    .tabcontent {
    display: none;
    padding: 6px 12px;
    border: 1px solid #ccc;
    border-top: none;
    }
    body {
    font-family: 'Anaheim';
    font-size: 1.2em;
    }

    #outside {
    background-color: lightgoldenrodyellow;
    padding-top: 25px;
    padding-bottom: 25px;
    }

    h1 {
    font-size: 1.5em;
    text-align: center;
    text-transform: capitalize;
    }

    form {
    /* Just to center the form on the page */
    margin: 0 auto;
    width: 70%;
    /* To see the limits of the form */
    padding: 1em;
    border: 1px solid #CCC;
    border-radius: 1em;
    
    }
    #survey-form {
    background-color: white;
    }

    fieldset { 
    border:1px solid lightgray;
    margin: 10px;
    }

    legend {
    font-weight: 700;
    }

    #number {
    width: 150px;
    }


    div + div {
    margin-top: 1em;
    }

    /* label {
    /* To make sure that all label have the same size and are properly align */
    /* display: inline-block; */
    /* width: 80px; */
    /* text-align: right; */
    } */

    input, textarea {
    /* To make sure that all text field have the same font settings
        By default, textarea are set with a monospace font */
    /* font: 1em sans-serif; */

    /* To give the same size to all text field */
    width: 200px;

    /*   -moz-box-sizing: border-box;
        box-sizing: border-box; */

    /* To harmonize the look & feel of text field border */
    border: 1px solid #999;
    }

    input:focus, textarea:focus {
    /* To give a little highligh on active elements */
    border-color: OrangeRed;
    }

    textarea {
    /* To properly align multiline text field with their label */
    vertical-align: top;

    /* To give enough room to type some text */
    height: 5em;

    /* To allow users to resize any textarea vertically
        It works only on Chrome, Firefox and Safari */
    resize: vertical;
    }

    .button {
    /* To position the buttons to the same position of the text fields */
    padding-left: 90px; /* same size as the label elements */
    }

    button {
    margin: .5em;
    font-size: 1em;
    text-transform: capitalize;
    background-color: red;
    color: white;
    border: none;
    padding: 5px;
    border-radius: 2px;
    
    }

    #submitbutton {
    display: flex; 
    justify-content: center;
    }


    </style>
   
</head>

<body class="bg-gray-100 h-screen antialiased leading-none">
    @yield('content')
</body>
</html>
