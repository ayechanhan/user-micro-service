import pymongo, secure, uvicorn
from auth0.authentication import Database, GetToken, RevokeToken, Users as Auth_Users
from auth0.management import Users, Roles, Jobs
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from config import settings
from schemas import User, ChangePasswordSchema, UserProfile, RegisterSchema, CreateUserSchema, UpdateUserSchema
from dependencies import validate_token, RoleValidator
from bson.objectid import ObjectId
from bson.errors import InvalidId
from token_verify import get_auth0_token

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.front_end_url],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=86400,
)

auth0_access_token = get_auth0_token()

auth0_database = Database(settings.domain, settings.client_id, timeout=30)
auth0_token = GetToken(settings.domain, settings.client_id, settings.client_secret)
auth0_revoke = RevokeToken(settings.domain, settings.client_id)
auth0_users = Users(settings.domain, auth0_access_token, timeout=30)
auth0_auth_users = Auth_Users(settings.domain)
auth0_roles = Roles(settings.domain, auth0_access_token)
auth0_jobs = Jobs(settings.domain, auth0_access_token)

# Connection to Mongodb
mongodb = pymongo.MongoClient(f"mongodb+srv://{settings.db_user}:{settings.db_password}@{settings.db_host}?retryWrites=true&w=majority", 27017)
database = mongodb['user-micro-service']
user_collection = database.users

@app.post("/auth", summary="Login to account")
def login(user: User):
    user_data = user_collection.find_one({"email": user.email})
    if user_data is None:
        raise HTTPException(
            status_code= status.HTTP_404_NOT_FOUND,
            detail="Invalid email or password"
        )
    try:
        result = auth0_token.login(username=user.email, password=user.password, realm="Username-Password-Authentication", scope="openid", audience=settings.audience)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.message)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"token": result['access_token'], "exp_in": result["expires_in"], "type": result["token_type"]}
    )

@app.post("/users/change_password", summary="Change password", dependencies=[Depends(validate_token)])
async def change_password(user: ChangePasswordSchema, Authorization: str = Header(None)):
    user_info = auth0_auth_users.userinfo(Authorization.split(" ")[-1])
    if user_info['email'] != user.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Email"
        )
    
    result = auth0_database.change_password(
        user.email,
        "Username-Password-Authentication",
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=result
    )

@app.get("/users/profile/", summary="Get current user profile", dependencies=[Depends(validate_token)])
async def user_profile(Authorization: str = Header(None)):
    token = Authorization.split(" ")[-1]
    user_id = auth0_auth_users.userinfo(token)['sub'].split("|")[-1]
    user_data = user_collection.find_one({"_id": ObjectId(user_id)}, {"password": False, "tenant": False, "client_id": False})
    user_data["_id"]  = str(user_data['_id'])
    return JSONResponse(status_code=status.HTTP_302_FOUND, content=user_data)
    

@app.put("/users/update_profile", summary="Update user profile", dependencies=[Depends(validate_token)])
async def update_profile(user: UserProfile, Authorization: str = Header(None)):
    user_info = auth0_auth_users.userinfo(Authorization.split(" ")[-1])
    user_id = user_info["sub"].split("|")[-1]
    user_data = user_collection.find_one({"_id": ObjectId(user_id)})
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND
        )
    result = user_collection.update_one(
        {"_id": ObjectId(user_id)}, [{"$set": {"user_metadata": {
        "firstName": user.firstname,
        "lastName": user.lastname,
        "gender": user.gender,
        "phone": user.phone,
        "birthDate": user.birthdate,
        "avatar": user.avatar,
        "address": user.address,
        "city": user.city,
        "postalCode": user.postalcode,
        "state": user.state,
        "primary": user.primary,
        "label": user.label
        }}}]
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=f"User: {user_id} is successfully updated"
    )

@app.put("/users/change_email/", summary="Change current user email", dependencies=[Depends(validate_token)])
async def change_email(user: ChangePasswordSchema, Authorization: str = Header()):
    token = Authorization.split(" ")[-1]
    user_id = auth0_auth_users.userinfo(token)['sub']
    update_email = auth0_users.update(user_id, {"email": user.email})
    if update_email:
        send_verification_email = auth0_jobs.send_verification_email({"user_id": user_id})
    return JSONResponse(status_code=status.HTTP_200_OK, content=f"Email updated and verification email sent to {user.email}")


@app.get("/users/{user_id}", summary="Find a user with given ID", dependencies=[Depends(RoleValidator(settings.admin_role, auth0_access_token))])
async def search_user_by_id(user_id: str):
    try:
        user_data = user_collection.find_one({"_id": ObjectId(user_id)},{
            "_id": 1,
            "email": 1,
            "user_metadata": 1,
        })
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid UserID")
    if user_data is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content="User not found"
        )
    else:
        user_data['_id'] = str(user_data['_id'])
        return JSONResponse(
            status_code=status.HTTP_302_FOUND,
            content=user_data
        )

@app.get("/users", summary="List all users", dependencies=[Depends(RoleValidator(settings.admin_role, auth0_access_token))])
async def list_all_users():
    user_data = user_collection.find({'role': "user"},{
        "_id": 1,
        "email": 1,
        "user_metadata": 1,
        "role": 1,
    })
    if user_data is None:
        return JSONResponse(status_code=status.HTTP_200_OK, content=[])
    else:
        result = auth0_roles.list_users(settings.user_role, 0, 25, False, )
        # result = []
        # for user in user_data:
        #     user["_id"] = str(user["_id"])
        #     result.append(user)
        return JSONResponse(status_code=status.HTTP_302_FOUND, content=result)
    
@app.delete("/users/{user_id}", summary="Delete specific user", dependencies=[Depends(validate_token)])
async def delete_user(user_id: str, Authorization: str = Header(None)):
    token = Authorization.split(" ")[-1]
    token_user_id = auth0_auth_users.userinfo(token)['sub'].split("|")[-1]
    if token_user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    try:
        result = auth0_users.delete(f"auth0|{user_id}")
        user_data = user_collection.delete_one({"_id": ObjectId(user_id)})
        return JSONResponse(status_code=status.HTTP_200_OK, content="User successfully deleted")
    except Exception as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error)
    
@app.post("/admin/create_user", summary="Create a user by admin", dependencies=[Depends(RoleValidator(settings.admin_role, auth0_access_token))])
async def create_user_by_admin(user: CreateUserSchema):
    roles = ["Admin", "User"]
    if user.role not in roles:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role must be Admin or User")
    try:
        result = auth0_database.signup(
            email = user.email,
            password=user.password,
            connection="Username-Password-Authentication"
        )
        role = settings.user_role if user.role == "User" else settings.admin_role
        assign_role = auth0_users.add_roles(f"auth0|{result['user_id']}", [role])
        return JSONResponse(
            status_code=status.HTTP_201_CREATED, content=result
        )
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=error
        )
    
@app.put("/admin/update_user", summary="Update user by admin", dependencies=[Depends(RoleValidator(settings.admin_role, auth0_access_token))])
async def update_user_by_admin(user: UpdateUserSchema):
    user_data = user_collection.find_one({"_id": ObjectId(user.id)})
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND
        )
    result = user_collection.update_one(
        {"_id": ObjectId(user.id)}, [{"$set": {"user_metadata": {
        "firstName": user.firstname,
        "lastName": user.lastname,
        "gender": user.gender,
        "phone": user.phone,
        "birthDate": user.birthdate,
        "avatar": user.avatar,
        "address": user.address,
        "city": user.city,
        "postalCode": user.postalcode,
        "state": user.state,
        "primary": user.primary,
        "label": user.label
        }}}]
    )
    if user.role is not None:
        list_roles = auth0_users.list_roles(f"auth0|{user.id}", 0,25,False)
        list_roles = [i["id"] for i in list_roles]
        remove_existing_role = auth0_users.remove_roles(f"auth0|{user.id}", list_roles)
        updated_role = settings.user_role if user.role == "User" else settings.admin_role
        assign_role = auth0_users.add_roles(f"auth0|{user.id}", [updated_role])
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=f"User: {user.id} is successfully updated"
    )

@app.delete("/admin/delete_user/{user_id}", summary="Delete a user by admin", dependencies=[Depends(RoleValidator(settings.admin_role, auth0_access_token))])
async def delete_user_by_admin(user_id: str):
    try:
        result = auth0_users.delete(f"auth0|{user_id}")
        user_data = user_collection.delete_one({"_id": ObjectId(user_id)})
        return JSONResponse(status_code=status.HTTP_200_OK, content="User successfully deleted")
    except Exception as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error)

@app.post("/users", summary="Register new user(s)")
async def register(user: RegisterSchema):
    user_data = user_collection.find_one({"email": user.email})
    if user_data is not None:
        raise HTTPException(
            status_code= status.HTTP_400_BAD_REQUEST,
            detail="Email already exist"
        )
    result = auth0_database.signup(
        email=user.email,
        password=user.password, 
        user_metadata=user.user_metadata ,
        connection='Username-Password-Authentication')
    assign_default_role = auth0_users.add_roles(f"auth0|{result['user_id']}", [settings.user_role])
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result
    )

@app.get("/admin/user_activity/{user_id}", summary="Get All User Activities", dependencies=[Depends(RoleValidator(settings.admin_role, auth0_access_token))])
async def get_activities(user_id: str):
    try:
        result = auth0_users.get_log_events(f"auth0|{user_id}", 0, 25, include_totals=False)
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
    except Exception as error:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

@app.post("/forget_password", summary="Forget Password")
async def forget_password(user: ChangePasswordSchema):
    try:
        result = auth0_database.change_password(
            user.email,
            "Username-Password-Authentication",
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
    except Exception as e:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e)

@app.post("/users/close_account", summary="Close Account", dependencies=[Depends(validate_token)])
async def close_account(Authorization: str = Header(None)):
    token = Authorization.split(" ")[-1]
    token_user_id = auth0_auth_users.userinfo(token)['sub'].split("|")[-1]
    try:
        close_account = user_collection.update_one({"_id": ObjectId(token_user_id)}, {"$set": {"status": "closed"}})
        block = auth0_users.update(f"auth0|{token_user_id}", {"blocked": True})
        return JSONResponse(status_code=status.HTTP_200_OK, content="Your account is closed")
    except:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Request")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host = "0.0.0.0",
        port = settings.port,
        reload = settings.reload,
        server_header=False
    )