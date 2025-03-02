<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Token;

/**
 * @OA\Info(
 *    title="Laravel v11 Passport API Documentation",
 *    version="1.0.0",
 * )
 */

class ApiController extends Controller
{


    // anotation to create Swagger Docume documentation
    /**
     * @OA\Post(
     * path="/api/register",
     * operationId="Register",
     * tags={"Register"},
     * summary="User Register",
     * description="User Register here",
     *     @OA\RequestBody(
     *         @OA\JsonContent(),
     *         @OA\MediaType(
     *            mediaType="multipart/form-data",
     *            @OA\Schema(
     *               type="object",
     *               required={"name","email", "password", "password_confirmation"},
     *               @OA\Property(property="name", type="text", example="Sanjay"),
     *               @OA\Property(property="email", type="text" ,example="sajay@gmail.com"),
     *               @OA\Property(property="password", type="password", example="123456"),
     *               @OA\Property(property="password_confirmation", type="password" ,example="123456"),
     *            ),
     *        ),
     *    ),
     *      @OA\Response(
     *          response=201,
     *          description="Register Successfully",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(
     *          response=200,
     *          description="Register Successfully",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(response=400, description="Bad request"),
     *      @OA\Response(response=404, description="Resource Not Found"),
     * )
     *
     * @OA\Post(
     *     path="/api/login",
     *     operationId="Login",
     *     tags={"Login"},
     *     summary="User Login",
     *     description="User Login here",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *            mediaType="multipart/form-data",
     *            @OA\Schema(
     *               type="object",
     *               required={"email", "password"},
     *               @OA\Property(property="email", type="string", example="sanjay@gmail.com"),
     *               @OA\Property(property="password", type="string", example="123456"),
     *            ),
     *        ),
     *        @OA\MediaType(
     *            mediaType="application/json",
     *            @OA\Schema(
     *               type="object",
     *               required={"email", "password"},
     *               @OA\Property(property="email", type="string", example="sanjay@gmail.com"),
     *               @OA\Property(property="password", type="string", example="123456"),
     *            ),
     *        ),
     *    ),
     *    @OA\Response(
     *        response=201,
     *        description="Login Successfully",
     *        @OA\JsonContent()
     *    ),
     *    @OA\Response(
     *        response=200,
     *        description="Login Successfully",
     *        @OA\JsonContent()
     *    ),
     *    @OA\Response(
     *        response=422,
     *        description="Unprocessable Entity",
     *        @OA\JsonContent()
     *    ),
     *    @OA\Response(response=400, description="Bad request"),
     *    @OA\Response(response=404, description="Resource Not Found"),
     * )
     * 
     *
     * @OA\Get(
     *     path="/api/profile",
     *     operationId="getProfile",
     *     tags={"Profile"},
     *     summary="Get user profile",
     *     description="Retrieve user profile information.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="Authorization",
     *         in="header",
     *         description="Authorization Token",
     *         required=true,
     *         @OA\Schema(
     *             type="string",
     *             default="Bearer your_access_token_here"
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successful operation",
     *         @OA\JsonContent()
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     *
     * @OA\SecurityScheme(
     *     securityScheme="bearerAuth",
     *     type="http",
     *     scheme="bearer",
     *     bearerFormat="JWT"
     * )
   
     */




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
        if (!empty($user)) {

            if (Hash::check($request->password, $user->password)) {
                $token = $user->createToken('auth_token')->accessToken;
                return response()->json([
                    'status' => true,
                    'message' => 'User logged in successfully',
                    'token' => $token,
                    'data' => []
                ]);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => "password didn't match",
                    'data' => []
                ]);
            }
        } else {
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
