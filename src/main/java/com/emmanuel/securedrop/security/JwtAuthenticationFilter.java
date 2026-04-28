package com.emmanuel.securedrop.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final String AUTHORIZATION = "Authorization";
	private static final String BEARER_PREFIX = "Bearer ";

	private final JwtService jwtService;

	public JwtAuthenticationFilter(JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		String authorizationHeader = request.getHeader(AUTHORIZATION);

		if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)
				&& SecurityContextHolder.getContext().getAuthentication() == null) {
			try {
				authenticate(request, authorizationHeader.substring(BEARER_PREFIX.length()));
			}
			catch (IllegalArgumentException ex) {
				SecurityContextHolder.clearContext();
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
				return;
			}
		}

		filterChain.doFilter(request, response);
	}

	private void authenticate(HttpServletRequest request, String token) {
		String username = jwtService.validateAndExtractUsername(token);
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				username,
				null,
				List.of(new SimpleGrantedAuthority("ROLE_USER")));
		authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}
}
