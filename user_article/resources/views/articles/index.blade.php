@extends('layouts.master')


@section('content')
<div class="container mx-auto">
    <div class="rounded p-4">
        <div class="bg-white rounded p-6 mb-6 flex justify-between">
            <div class="p-2">
                <span class="font-bold text-lg">Articles</span> <small>({{ $articles->count() }})</small>
            </div>
            <div class="p-4 w-64">
                <form action="{{ url('search') }}" method="get">
                    <div class="form-group">
                        <input type="text" name="q" class="border p-2 w-full" placeholder="Search..."
                            value="{{ request('q') }}" />
                    </div>
                </form>
            </div>
        </div>
        <div class="row">
            <div class="column">
            <div id="Source" class="tabcontent1">
                    
                    <table class="table-auto">
                        <thead>
                            <tr>
                                <th class="px-4 py-2">Original Sources</th>
                            </tr>
                        </thead>
                        <tbody>
                        
                            @forelse ($articles as $article)
                            <tr>
                                <td class="border px-4 py-2">{{ $article->content }}</td>  
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
            <div>
            
    
            <div class="column">
                <div class="tab">
                    <button class="collapsible" >Dashboard</button>
                    

                    <button class="collapsible" >Snopes</button>
                    
                 
                    <button class="collapsible" >Survey</button>
                    
                </div>

                <div class="content">
                    <tbody>
                            
                            @forelse ($articles as $article)
                            <tr>
                                <td class="border px-4 py-2">{{ $article->keycontent }}</td>  
                            </tr>
                            @empty
                            <tr>
                                <td>No Reference found</td>
                            </tr>
                            @endforelse
                    </tbody>
                </div>

                <div class="content">
                    
                        <table class="table-auto">
                            <thead>
                                <tr>
                                    <th class="px-4 py-2">Title</th>
                                    <th class="px-4 py-2">Author</th>
                                    <th class="px-4 py-2">Time</th>
                                    <th class="px-4 py-2">Claim</th>
                                </tr>
                            </thead>
                            <tbody>
                                @forelse ($articles as $article)
                                <tr>
                                    <td class="border px-4 py-2">{{ $article->title }}</td>
                                    <td class="border px-4 py-2">{{ $article->author }}</td>
                                    <td class="border px-4 py-2">{{ $article->time }}</td>
                                    <td class="border px-4 py-2">{{ $article->claim }}</td>
                                    
                                </tr>
                                @empty
                                <tr>
                                    <td>No Articles found</td>
                                </tr>
                                @endforelse
                            </tbody>
                        </table>
                </div>

                <div class="content">
                    <script src="https://cdn.freecodecamp.org/testable-projects-fcc/v1/bundle.js"></script>
                    <!-- head - Googlefonts link -->

                    <div id="outside">
                    <form id="survey-form" action="/my-handling-form-page" method="post">
                    <h1 id="title">Website Survey</h1>
                    
                    
                    <!-- ------------------Personal Details---------------------------- -->
                    <fieldset>
                        <!-- groups of widgets that share the same purpose, for styling and semantic purposes -->
                        <legend>Personal Details</legend>
                        <!-- formally describes the purpose of the fieldset it is included inside. -->
                        <div>
                        <label id="name-label" for="name">Name:</label>
                        <input type="text" required id="name" name="user_name" placeholder="Enter name here">   </div>
                        <div>
                        <label for="address-label">Address:</label>
                        <input type="Address" id="address" name="Address" placeholder="Enter address here">   </div>
                        <div>
                        <label id="email-label" for="Email">Email:</label>
                        <input type="email" required id="email" name="user_email" placeholder="Enter email here">   </div>
                        <div>
                        <label id="number-label" for="phone">Phone Number:</label>
                        <input type="number" id="number" name="user_name" placeholder="Enter 10 digit number" min="1" max="9">  </div>
                        <div>
                        

                        <!-- ------------------Radio Buttons-------------------------------- -->
                        <div>
                        <label for="Gender">Gender</label>
                        <p>
                            <input type="radio" name="gender" value="male" checked> Male<br>
                            <input type="radio" name="gender" value="female"> Female<br>
                            <input type="radio" name="gender" value="other"> Other
                        </p>
                        </div>
                        <label for="date-label">Date of Proposed Outing:</label>
                        <input type="date" name="bday">
                    
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
                            </div>
                        </fieldset>

                    <!-- --------------------Text Areas------------------------------ -->
                    
                    <fieldset>
                        <legend>Essay Section</legend>
                        <div>
                        <label for="msg"></label>
                        <p> In 50 words or more to show how you like this website</p>
                        <textarea id="msg" name="user_message" rows="4" cols="50" placeholder="Enter Text Here"></textarea>   </div>
                        <div>
                        
                    </fieldset>

                    <div id="submitbutton">
                        <button type="submit" id="submit">Send your information</button>   </div>

                    </form>
                    </div>
                
                </div>
                
                    <!-- https://developer.mozilla.org/en-US/docs/Learn/HTML/Forms/Form_validation -->
                </div>
                
            </div>
            <script>
                    var coll = document.getElementsByClassName("collapsible");
                    var i;

                    for (i = 0; i < coll.length; i++) {
                    coll[i].addEventListener("click", function() {
                        this.classList.toggle("active");
                        var content = this.nextElementSibling;
                        if (content.style.display === "block") {
                        content.style.display = "none";
                        } else {
                        content.style.display = "block";
                        }
                    });
                    }
                    </script>    
            
        </div>
    </div>
</div>
@stop



