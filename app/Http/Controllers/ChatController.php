<?php
namespace App\Http\Controllers;

use App\User;
use Illuminate\Database;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\View\View;

class ChatController extends Controller {

    public function __construct()
    {
    }

    public function index()
    {
        return view('chat');
    }

    public function login()
    {
    }

    public function create() {

        $status = 'success';

        $login = $_POST['login'];
        $password = $_POST['password'];

        //TODO validation

        $user = User::firstOrNew(['name' => $login]);
        if (isset($user->id) AND $user->password == $password)
        {
            $status = 'login';
            $_SESSION['id'] = $user->id;
            $_SESSION['name'] = $user->name;
        }
        elseif (isset($user->id) AND $user->password != $password)
        {
            $status = 'error_password';
        }
        else
        {
            $user->password = $password;
            $user->save();
            $status = 'register';
        }

        if ($status == 'login')
        {
            $response = array(
                'status' => 'success',
                'user' => $user,
                'msg' => 'Successfully login!',
            );
        }
        elseif ($status == 'register')
        {
            $response = array(
                'status' => 'success',
                'user' => $user,
                'msg' => 'Successfully register!',
            );
        }
        elseif ($status == 'error_password')
        {
            $response = array(
                'status' => 'error',
                'user' => $user,
                'msg' => 'Wrong login/password',
            );
        }


        return Response::json( $response );
    }

}
