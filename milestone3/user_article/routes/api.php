<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
Use App\Article;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});


Route::group(['middleware' => 'auth:api'], function() {
    Route::get('articles', 'ArticlesController@index');
    Route::get('articles/{article}', 'ArticlesController@show');
    Route::post('articles', 'ArticlesController@store');
    Route::put('articles/{article}', 'ArticlesController@update');
    Route::delete('articles/{article}', 'ArticlesController@delete');
});
