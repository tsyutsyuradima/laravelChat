<?php
namespace App\Http\Controllers;

use App\History;
use App\User;
use Illuminate\Database;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Session;
use Illuminate\View\View;

class ChatController extends Controller {

    public function __construct()
    {
    }

    public function index()
    {
        Session::put('lustMessageId', 0);

        return view('chat');
    }

    public function getHistory()
    {
        $historyQuery = DB::select('SELECT * FROM history WHERE id > (SELECT MAX(id) - 10 FROM history)');
        $lustMessageId = DB::select('SELECT id FROM history ORDER BY id DESC LIMIT 1');
        Session::put('lustMessageId', $lustMessageId[0]->id);
        $response = array(
            'status' => 'success',
            'history' => $historyQuery,
        );
        return Response::json( $response );
    }

    public function sendMessage()
    {
        $name = Session::get('name');
        $message = $_POST['message'];

        DB::insert('INSERT INTO history (name, message) VALUES (?, ?)', [$name, $message]);
        $lustMessageId = Session::get('lustMessageId');
        $lustMessageId++;
        Session::put('lustMessageId', $lustMessageId);
        $response = array(
            'status' => 'success',
            'name' => $name,
            'message' => $message
        );
        return Response::json( $response );
    }

    public function checkHistory()
    {
        $lustMessageId = Session::get('lustMessageId');
        $topMessageId = DB::select('SELECT id FROM history ORDER BY id DESC LIMIT 1');
        $top = $topMessageId[0]->id;
        if($top > $lustMessageId)
        {
            $lustMessageId++;
            $messages = DB::select("SELECT * FROM history WHERE id BETWEEN '". $lustMessageId ."' AND '". $top ."';");
            Session::put('lustMessageId', $top);
            $response = array(
                'status' => 'update',
                'messages' => $messages,
            );
        }
        else
        {
            $response = array(
                'status' => 'no-update',
                'messages' => $lustMessageId,
            );
        }
        return Response::json( $response );
    }

    public function login()
    {
        $login = $_POST['login'];
        $password = $_POST['password'];

        //TODO validation

        $user = User::firstOrNew(['name' => $login]);
        if (isset($user->id) AND $user->password == $password)
        {
            $response = array(
                'status' => 'success',
                'user' => $user,
                'msg' => 'Successfully login!',
            );
            Session::put('name',$login);
        }
        elseif (isset($user->id) AND $user->password != $password)
        {
            $response = array(
                'status' => 'error',
                'user' => $user,
                'msg' => 'Wrong login/password',
            );
        }
        else
        {
            DB::insert('INSERT INTO user (name, password) VALUES (?, ?)', [$login, $password]);
            $user->password = $password;
            $user->name =  $login;
            Session::put('name',$login);

            $response = array(
                'status' => 'success',
                'user' => $user,
                'msg' => 'Successfully login! With new user',
            );
        }
        return Response::json( $response );
    }
}
