# Exceptions

The HTTP exceptions crudauth raises. All subclass `CustomException`, which is a FastAPI
`HTTPException`, so they propagate with the right status code and headers.

::: crudauth.exceptions.CustomException

::: crudauth.exceptions.BadRequestException

::: crudauth.exceptions.NotFoundException

::: crudauth.exceptions.ForbiddenException

::: crudauth.exceptions.UnauthorizedException

::: crudauth.exceptions.UnprocessableEntityException

::: crudauth.exceptions.DuplicateValueException

::: crudauth.exceptions.RateLimitException

::: crudauth.exceptions.SudoLockoutError

::: crudauth.exceptions.CSRFException
