<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Survey;
class SurveyController extends Controller
{
    
    public function index()
    {
        $surveys = Survey::all();
        return view('surveys.index', ['surveys' => $surveys]);
    }
    
    public function show(Survey $id)
    {
        return view('surveys.show', ['survey' => $id]);
    }
    
    
    public function add()
    {
        return view('surveys.add');
    }
}
