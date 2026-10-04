package com.github.guoyyit.srpauthenticationjava.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Translates exceptions into a uniform JSON envelope with a distinguishable
 * error code. Protocol violation messages never contain password material.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    @ResponseBody
    public org.springframework.http.ResponseEntity<Map<String, Object>> handleApi(
            ApiException ex) {
        return org.springframework.http.ResponseEntity.status(ex.getStatus())
                .body(body(ex.getCode(), ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseBody
    public org.springframework.http.ResponseEntity<Map<String, Object>> handleUnreadable(
            HttpMessageNotReadableException ex) {
        return org.springframework.http.ResponseEntity.badRequest()
                .body(body("MALFORMED_MESSAGE", "request body is not valid"));
    }

    @ExceptionHandler(Exception.class)
    @ResponseBody
    public org.springframework.http.ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex) {
        return org.springframework.http.ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body("INTERNAL_ERROR", "request could not be processed"));
    }

    private static Map<String, Object> body(String code, String message) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("error", code);
        map.put("message", message);
        return map;
    }
}
