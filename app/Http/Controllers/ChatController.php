<?php
namespace App\Http\Controllers;

class ChatController extends Controller {

    public function __construct()
    {
    }

    public function index()
    {
        return view('chat');
    }
}
