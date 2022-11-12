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