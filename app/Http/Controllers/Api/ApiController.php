<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Token;
class ApiController extends Controller
{
    public function register(Request $request)
    {    
        //validation
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|confirmed',
        ]);
        //create user
       User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
        //return
        return response()->json([
            'status' => true,
            'message' => 'User created successfully',
        'data' => []
        ]);
    }

    public function login(Request $request)
    {
        //validation
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        //email check
        $user = User::where('email', $request->email)->first();
        //password
        if(!empty($user)){
            
                if(Hash::check($request->password, $user->password)){
                    $token = $user->createToken('auth_token')->accessToken;
                    return response()->json([
                        'status' => true,
                        'message' => 'User logged in successfully',
                        'token' => $token,
                        'data' => []
                    ]);
                }else{
                    return response()->json([
                        'status' => false,
                        'message' => "password didn't match",
                        'data' => []
                    ]);
                }

        }else{
            return response()->json([
                'status' => false,
                'message' => 'Invalid email or password',
                'data' => []
            ]);
        }
    
        }

        //auth token
    

    
public function profile()
{
    $user = Auth::user();

    if (!$user) {
        return response()->json([
            "status" => false,
            "message" => "Unauthorized access",
            "data" => []
        ], 401);
    }

    return response()->json([
        "status" => true,
        "message" => "Profile information",
        "data" => $user
    ]);
}


public function logout()
{
    $user = Auth::user(); // Get the authenticated user

    if (!$user) {
        return response()->json([
            "status" => false,
            "message" => "User not authenticated"
        ], 401);
    }

    // Revoke the current access token
    Token::where('user_id', $user->id)->where('revoked', false)->update(['revoked' => true]);
    return response()->json([
        "status" => true,
        "message" => "User logged out successfully"
    ]);
}
}
