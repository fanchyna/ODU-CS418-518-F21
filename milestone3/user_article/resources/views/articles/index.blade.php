@extends('layouts.master')

@section('content')
<div class="container">
    <div>
        <div>
            <div style="text-align: center" id="search-text-voice">
                <span><h3>Articles ({{ $articles->count() }})</h3>
            </div>
            <div style="text-align: center" >
                <form action="{{ url('search') }}" method="get">
                    <div class="form-group" action="javascript:void(0)">
                        <input type="text" spellcheck="true" name="q" id='q' size="40" placeholder="Type or Speak to Search..." value="{{ request('q') }}"/>
                        <img onclick="startDictation()" src="{{asset('/voice.png')}}" width="30" height="30" />
                        
                    </div>
                </form>
                
                <div style="text-align: center"><h3>Highlight Search Result</h3>
                <form action="javascript:void(0)" method="" id="searchBar" name="searchBar">
                <input name="search" id="search" type="text" size="25" maxlength="25" placeholder="content to highlight">
                <input name="search_button" type="button" value="Highlight" onClick="findAndHighlight()">
                </form>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="column">
            <div id="Source" class="tabcontent1">
                    
                    <table>
                        <thead>
                            <tr>
                                <th class="px-4 py-2"><h3>Original Sources</h3></th>
                            </tr>
                        </thead>
                        <tbody>
                        
                            @forelse ($articles as $article)
                            <tr>
                                <td id="panels" class="border px-4 py-2">{{ $article->content }}</td>  
                            </tr>
                            @empty
                            <tr>
                                <td>No Reference found</td>
                            </tr>
                            @endforelse
                        </tbody>
                    </table>
            </div> 
            </div>
        
            
    
            <div class="column">
                <div class="container">
                    <ul class="nav nav-tabs" >
                        <li class='active'>
                            <a class="nav-link active" data-toggle='tab' href="#home"><h3>Dashboard</h3></a>
                        </li>
                        <li class='nav nav-tabs'>
                            <a class="nav-link active" data-toggle='tab' href="#menu1" onClick="lurl();"><h3>Snope</h3></a>
                        </li>
                        <li class='nav nav-tabs'>
                            <a class="nav-link active" data-toggle='tab' href="#menu2"><h3>Survey</h3></a>
                        </li>
                    </ul>

                    <div class="tab-content">
                        <div id="home" class="tab-pane fade in active">  
                        <tbody>        
                            @forelse ($articles as $article)
                            <tr>
                            <td id="panels" class="border px-4 py-2">{{ $article->keycontent }}</td>  
                            <br>
                            <br>
                            </tr>
                            @empty
                            <tr>
                            <td>No Reference found</td>
                            </tr>
                            @endforelse
                        </tbody>
                        </div>

                        <div id="menu1" class="tab-pane fade">
                                <div id="snope">
                                @forelse ($articles as $article)
                                @empty
                                <tr>
                                <td>No Articles found</td>
                                </tr>
                                 @endforelse
                                </div>
                            
                        </div>
                        
                        <div id="menu2" class="tab-pane fade">
                        <div id="outside">
                        <form id="survey-form" action="/submit" method="POST">
                        @csrf       
                        @method('PUT')            
                        <!-- ------------------Personal Details---------------------------- -->
                        <fieldset>
                            <!-- groups of widgets that share the same purpose, for styling and semantic purposes -->
                            <legend>Personal Details</legend>
                            <!-- formally describes the purpose of the fieldset it is included inside. -->
                            <div>
                            <label id="name-label" for="name">Name:</label>
                            <input type="text" required id="name" name="user_name" placeholder="Enter name here">   
                            </div>
                            <div>
                            <label for="address-label">Address:</label>
                            <input type="Address" id="address" name="Address" placeholder="Enter address here">   
                            </div>
                            <div>
                            <label id="email-label" for="Email">Email:</label>
                            <input type="email" required id="email" name="user_email" placeholder="Enter email here">   
                            </div>                          
        
                            
                            <!-- ------------------Radio Buttons-------------------------------- -->
                            <div>
                            <label for="Gender">Gender</label>
                            <p>
                                <input type="radio" name="gender" value="male" checked> Male
                                <input type="radio" name="gender" value="female"> Female
                                <input type="radio" name="gender" value="other"> Other
                            </p>
                            </div>
                             
                        </fieldset>                
                        
                        <!-- -----------------Dropdown menus--------------------------------- -->
                        
                        <fieldset>                            
                            <label for="politics">Education Level Completed:</label>
                            <select id="dropdown2">
                            <option value="University">University</option>
                            <option value="College">College</option>
                            <option value="Secondary">High School</option>  
                            <option value="None">None</option>
                            </select>
                                
                        </fieldset>

                        <!-- --------------------Text Areas------------------------------ -->
                        
                        <fieldset>
                            <legend>Essay Section</legend>
                            <div>
                            
                            <p> In 50 words or more to show how you like this website</p>
                            <textarea id="msg" name="user_message" rows="10" cols="50" placeholder="Enter Text Here" style="overflow:scroll;"></textarea>   
                            </div>
                            
                            
                        </fieldset>

                        <div id="submitbutton">
                            <button type="submit" id="submit">Send your information</button>   
                        </div>

                        </form>
                        </div>
                        </div>

                        
                        </div>
                    </div>
                
                </div>
            </div>
        </div>
</div>
@stop
                      