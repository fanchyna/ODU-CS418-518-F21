<?php

use App\Http\Controllers\HomeController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
 */

Route::get('/', function () {
    return view('welcome');
});

Route::middleware(['auth:sanctum', 'verified'])->get('/dashboard', function (Request $request) {
    $role = Auth::user()->verified_user;
    if ($role == '1') {
        return view('dashboard');
    } else {
        echo '<script type="text/javascript">alert("In order to login. You need to get access from admin!");</script>';
        Cookie::queue(Cookie::forget('laravel_session'));
        Cookie::queue(Cookie::forget('XSRF-TOKEN'));
        // return back();
        // return redirect()->back()->with('alert', 'Deleted!');
        return back();
    }
})->name('dashboard');

Route::get('redirect_to', [HomeController::class, 'index'])->middleware(['auth:sanctum', 'verified']);

Route::group(['middleware' => 'auth'], function () {
    Route::resource('users', \App\Http\Controllers\UsersController::class);
});

Route::get('/snoopes', function () {
    return view('dashboard');
})->name('snoopes');

Route::get('/survey', function () {
    return view('dashboard');
})->name('survey');
