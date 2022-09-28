# Keleya Skill-Check

## Backend

The task here is to finish the provided 'barebone' backend by implementing all endpoints and required functionality, and setting up the database following these requirements. The goal of this 'project' is to end up with a working REST API with CRUD endpoints for a simple user management, paired with authorization and authentication methods.

For the backend we are using two modern frameworks, [NestJS](https://docs.nestjs.com/) and [Prisma](https://www.prisma.io/docs/getting-started) running on Node 14. To make the database setup as simple as possible, we will use a SQlite DB. One part of this task will thus be, to familiarize yourself with the technology stack.

The repository as provided throws NotImplementedException() for the missing functions, as well as misses the data structures and database.

### Types

Data is being transferred between functions using Data Transfer Objects. This need to be implemented in accordance with the data model. Optionally, data validation should be implemented as well to assure that valid data is being sent into the application.

### Database

The database should follow this schema:
![backend schema](backend_schema.png)

Command lines:

- `npx prisma migrate dev` for migration
- `npx prisma db seed` for seeding

### Endpoints

- GET /user should query for users with these optional filtering parameters:
  - `limit` Limit the number of results returned
  - `offset` Skip the first n results
  - `updatedSince` Return only items which were updated since Date.
  - `id` An Array of id(s) to limit the query to
  - `name` a LIKE search for names
  - `credentials` include the related credentials in result
  - `email` search for matching email
- GET /user/:id should return one specific user with that id
- (public) POST /user should create a new user with credentials
- PATCH /user should update a user if it exists and should update credentials if they exist IF the user has not been deleted previously
- DELETE /user marks the user as deleted and also removes related credentials rows, but does NOT remove the user row itself
- (public) POST /user/authenticate authenticates the user with an email/password combination and returns a boolean
- (public) POST /user/token authenticates the user with an email/password combination and returns a JWT token
- (public) POST /user/validate validates a Bearer token sent via authorization header and returns a boolean

### Security

- Endpoints marked (public) should allow access without authorization
- Endpoints **not** marked (public) should check JWT tokens and map to users
- Health Check endpoints should be public and no JWT should be required
- Non-public endpoints called by Admin users should allow requests to modify all users, while regular users should locked into their own user - they are only allowed to work on their own user id
- Passwords need to be hashed and salted

### Testing

- If possible, unit tests should check the functionality of the various endpoints and services
- Alternatively, discuss why certain tests were not implemented, necessary or useful, or suggest a test environment

### Extra

- Discuss improvements to the data models or endpoints
- Feel free to suggest other solutions to implement similar projects (but for this skill check, do use the given tech stack as provided here)

### How to do the skill check

- Fork this repository
- Make modifications as you see fit
- Add all your notes into this readme
- Send us the link to your fork
- Tell us how long it took you to get the repository to the state you sent us - remember: it's ok to take time if it's done properly.
- Import Hiring Backend Test.postman_collection.json into the latest Postman client and run the collection tests. Depending on how you seed your database, some tests may need to be adjusted for ids. Please take a screenshot of the results like this one:
- ![postman_tests.png](postman_tests.png)
- Send us this screenshot as well as the export of your postman tests.
- the following should run without errors:

```
yarn
npx prisma migrate reset
yarn test
```

### Your Notes Below Here

- The Postman_collection is commited to repository. Below are the Test_Results.

### As a user

- ![Tests as user](reports\Tests_As_User1Screenshot.png)
- ![Tests as user](reports\Tests_As_User2.png)

### As a admin

- ![Tests as Admin](reports\Tests_As_Admin_1Screenshot.png)
- ![Tests as Admin](reports\Tests_As_Admin_2Screenshot.png)

### E2E Tests

- ![Unit tests](reports\E2E_tests.png)
- ![Unit tests](reports\E2E_Unit_test.png)

### Improvements

- Approach:

  - We can separate authentication endpoints and user CRUD endpoints to make appliaction manageable.

- JWTToken:

  - We can store the JWT secret to cloud service for eg: AWS Secret Manager and fetch that secret using library function. This makes app more secure.
  - Using single access token requires user to relogin after expiration duration. And as acess tokens are valid for short time.
  - We can introduce /refresh endpoint and logic for provisioning refresh token(this token have long validity in days) to the user.
  - Upon expiration user will have to just refresh token using refresh API (without Username/Password), this would require use of cookies.
  - Refresh token should be stored encrypted to hash and then store in DB to avoid Data Leaks.

- Data Models :

  - We can create single table instead of two which includes two more columns hash, hashRt(refresh token hash).
    Or
  - We can just introduce one more column in credentials table as hashRt.(With the aim of keeping sensitive user data in separate table)

- Endpoints:

  - /refresh token to refresh token and avoild multiple login requests from same user.
  - /createBulk or /createMany endpoint for admins. So single api call will create many users.
  - /deleteBulk or /deleteMany endpoint for admins to delete outdated users data as per GDPR policy.
    To be more performant for bulk endpoint we should run queries in batches.

- Unit Tests:

  - More unit tests should be added for controller and security checks.

- Dockerize App

  - It is best to create docker container image of the app. It makes it easy to maintain and brings agility.

- ...
