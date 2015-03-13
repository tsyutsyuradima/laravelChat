<?php
/**
 * Created by IntelliJ IDEA.
 * User: dmytroTsyutsyura
 * Date: 13.03.15
 * Time: 19:18
 * To change this template use File | Settings | File Templates.
 */
namespace App\Http\Controllers;

class ChatController extends Controller {

    /*
    |--------------------------------------------------------------------------
    | Home Controller
    |--------------------------------------------------------------------------
    |
    | This controller renders your application's "dashboard" for users that
    | are authenticated. Of course, you are free to change or remove the
    | controller as you wish. It is just here to get your app started!
    |
    */

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {

    }

    /**
     * Show the application dashboard to the user.
     *
     * @return Response
     */
    public function index()
    {
        return view('chat');
    }

}
