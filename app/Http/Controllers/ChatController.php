<?php
namespace App\Http\Controllers;

use App\User;
use Illuminate\Database;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

class ChatController extends Controller {

    public function __construct()
    {
    }

    public function index()
    {
        if ($_POST) {
            echo json_encode(['result'=>'success']);
        }
        else {
            return view('chat');
        }
    }

    public function login()
    {
    }

    public function create() {
//        //check if its our form
//        if ( Session::token() !== Input::get( '_token' ) ) {
//            return Response::json( array(
//                'msg' => 'Unauthorized attempt to create setting'
//            ) );
//        }
//
//        $setting_name = Input::get( 'setting_name' );
//        $setting_value = Input::get( 'setting_value' );
//
//
        $response = array(
            'status' => 'success',
            'msg' => 'Setting created successfully',
        );

        return Response::json( $response );
    }

}
