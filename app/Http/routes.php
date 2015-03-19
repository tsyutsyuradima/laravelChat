<?php
Route::match(['get','post'],'/', 'ChatController@index');
Route::match(['get','post'],'login', 'ChatController@login');
Route::match(['get','post'],'getHistory', 'ChatController@getHistory');
Route::match(['get','post'],'checkHistory', 'ChatController@checkHistory');
Route::match(['get','post'],'sendMessage', 'ChatController@sendMessage');

Route::get('home', 'HomeController@index');

Route::controllers([
    'auth' => 'Auth\AuthController',
    'password' => 'Auth\PasswordController',
]);