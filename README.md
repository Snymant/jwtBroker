# jwtBroker
jwt Tokenizer written in Java. Includes JEE compatible Filter.

usage
In your web.xml setup add:
```xml    
    <filter>
        <filter-name>JwtFilter</filter-name>
        <filter-class>za.co.bronkode.jwtbroker.JwtFilter</filter-class>
        <init-param>
            <param-name>privateKey</param-name>
            <param-value>secret password shared with no one</param-value>
        </init-param>
        <init-param>
            <param-name>issuer</param-name>
            <param-value>co.za.bronkode</param-value>
        </init-param>
        <init-param>
            <param-name>expiryMinutes</param-name>
            <param-value>60</param-value>
        </init-param>
        <init-param>
            <param-name>claimClass</param-name>
            <param-value>za.co.bronkode.jwtbroker.TokenClaim</param-value>
        </init-param>
        
    </filter>
    <filter-mapping>
        <filter-name>JwtFilter</filter-name>
        <url-pattern>/api/*</url-pattern>
    </filter-mapping>
```
Create a rest endpoint for authenticating
```java
@Path("login")
    public class LoginResource {

    @Context
    private UriInfo context;

    @Inject
    AuthProvider auth;

    /**
     * Creates a new instance of LoginResource
     */
    public LoginResource() {
    }

    /**
     * Tests the current auth header.
     *
     * @return an instance of java.lang.String
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public TokenClaim getJson() {
        //TODO return proper representation object
        Token token = auth.getToken();
        if (auth.isValidToken()) {

            return token.getClaim(TokenClaim.class);
        } else {
            return null;
        }
    }

    /**
     * PUT method for updating or creating an instance of LoginResource
     *
     * @param content representation for the resource
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject putJson(JsonObject content) {
        Token t = new Token();
        try {
            TokenClaim newClaim = Tokenizer.getNewClaim();
            newClaim.setUserName(content.getString("username"));
            t.setHeader(new TokenHeader());
            t.setClaim(newClaim);
            String encodedToken = Tokenizer.EncodeToken(t);
            JsonObject result = Json.createObjectBuilder().add("success", "true")
                    .add("jwtToken", encodedToken)
                    .build();
            return result;
        } catch (Exception ex) {
            Logger.getLogger(LoginResource.class.getName()).log(Level.SEVERE, null, ex);
            JsonObject result = Json.createObjectBuilder().add("success", "false")
                    .build();
            return result;
        }

    }
}
```

Client should add returned token to Authentication Http Header example:
curl -X GET -H"Accept: application/json" -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjby56YS5icm9ua29kZSIsImlhdCI6MTQ1MTkwMjQ5ODIxOSwiZXhwIjowLCJ1c2VySWQiOm51bGwsInVzZXJOYW1lIjoidGhldW5zIiwiY2xpZW50SWQiOm51bGwsImNsaWVudE5hbWUiOm51bGwsInJvbGVzIjpudWxsfQ==./klZgSjD0NwbV1v3xVC/zrv8A8qqcmlpoo2aM0mbDJI=" "http://127.0.0.1:8080/jwtSample/api/login" -i
