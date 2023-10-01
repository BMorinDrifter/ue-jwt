UeJwt
=====

Purpose
-------

Simple Jwt code written in idiomatic Unreal Engine C++ for reading 
[Json Web Tokens](https://jwt.io/).  Originally written for Superior when interactions 
with the latest Steamworks SDK caused problems with jwtcpp due to usage of exceptions 
to capture routine error conditions.

This library does not use C++ exceptions and leverages the existing code in Unreal
Engine for working with Json and OpenSSL to reduce code/memory bloat from pulling in 
the dependency chain of another ecosystem.

Credit
------

This library was built by reverse engineering [jwtcpp](https://github.com/Thalhammer/jwt-cpp).
Figuring out the right SSL calls without a reference implementation would have been extremely
time consuming.

Thanks to Ray Davis (CEO Drifter) for giving me permission to open source this solution.