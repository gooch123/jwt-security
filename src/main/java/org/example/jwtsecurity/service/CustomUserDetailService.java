package org.example.jwtsecurity.service;

import lombok.RequiredArgsConstructor;
import org.example.jwtsecurity.entity.UserEntity;
import org.example.jwtsecurity.dto.CustomUserDetails;
import org.example.jwtsecurity.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByUsername(username);

        if (userEntity != null) {

            return new CustomUserDetails(userEntity);
        }

        return null;
    }
}
