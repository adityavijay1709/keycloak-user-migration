package com.uniauth.code.keycloak.providers.rest.rest;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface RestUserClient {

    @GET
    @Path("/{username}/")
    Response findByUsername(@PathParam("username") String username);

    @GET
    @Path("/{phone}/")
    Response findByPhone(@PathParam("phone") String phone);

    @POST
    @Path("/{username}/")
    Response validatePassword(@PathParam("username") String username, UserPasswordDto passwordDto);

    @POST
    @Path("/password/reset")
    Response updatePassword(UpdatePasswordDto updatePasswordDto);
}
