<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function login(Request $request){
        $email = $request->email;
        $password = $request->password;

        // check if field isn't empty
        if(empty($email) || empty($password)){
            return response()->json([
                'status' => false,
                'message' => 'You should fill all fields'
            ]);
        }

        try{
            $tokenRequest = $request->create(           
                config('service.passport.login_endpoint'),
                'POST'
            );
    
            $tokenRequest->request->add([
                "client_secret" => config('service.passport.client_secret'),
                "grant_type" => "password",
                "client_id" => config('service.passport.client_id'),
                "username" => $email,
                "password" => $password,
            ]);
    
            $response = app()->handle($tokenRequest);
            return $response;
        } catch (Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()]);
        }

    }

    public function register(Request $request){
        $name = $request->name;
        $email = $request->email;
        $password = $request->password;

        // check if field isn't empty
        if(empty($name) || empty($email) || empty($password)){
            return response()->json([
                'status' => false,
                'message' => 'You must fill all the field'
            ]);
        }
        // check if email is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)){
            return response()->json([
                'status' => false,
                'message' => 'You must enter a valid email'
            ]);
        }

        // Check if the password is greater than 5 character
        if(strlen($password) < 6){
            return response()->json([
                'status' => false,
                'message' => 'Password should be min 6 character'
            ]);
        }

        // Check if user already exist
        if (User::where('email','=',$email)->exists()) {
            return response()->json([
                'status' => false,
                'message' => 'User already exists with this email'
            ]);
        }

        // create new user
        try {
            $user = new User();
            $user->name = $name;
            $user->email = $email;
            $user->password = app('hash')->make($password);

            if($user->save()){
                // will call login method
                return $this->login($request);
            }
        } catch (Exception $e){
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ]);
        }
    }

    public function logout(Request $request){
        try {
            auth()->user()->tokens()->each(function ($token){
                $token->delete();
            });
            return response()->json([
                'status' => true,
                'message' => 'Logged out successfully'
            ]);
        } catch (Exception $e){
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ]);
        }
    }
}
