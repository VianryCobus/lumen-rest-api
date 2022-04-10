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

        // Check if field is empty
        if(empty($email) || empty($password)){
            return response()->json([
                'status' => false,
                'message' => 'You must fill all the fields'
            ]);
        }

        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function register(Request $request){
        $name = $request->name;
        $email = $request->email;
        $password = $request->password;

        // check if field is empty
        if(empty($name) || empty($email) || empty($password)){
            return response()->json([
                'status' => false,
                'message' => 'You must fill all the fields'
            ]);
        }

        // check if email is valid
        if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
            return response()->json([
                'status' => false,
                'message' => 'You must enter a valid email'
            ]);
        }

        // check if password is greater than 5 character
        if(strlen($password) < 6){
            return response()->json([
                'status' => false,
                'message' => 'Password should be min 6 character'
            ]);
        }

        // check if user already exist
        if(User::where('email','=',$email)->exists()){
            return response()->json([
                'status' => false,
                'message' => 'User alreadt exists with this email'
            ]);
        }

        // Create new user
        try{
            $user = new User();
            $user->name = $name;
            $user->email = $email;
            $user->password = app('hash')->make($password);

            if($user->save()){
                return $this->login($request);
            }
        } catch(Exception $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ]);
        }
    }

    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    protected function respondWithToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
