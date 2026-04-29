package br.com.forum_hub.domain.usuario;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService implements UserDetailsService {

    private final UsuarioRepository repository;

    public UsuarioService(UsuarioRepository repository) {
        this.repository = repository;
    }

    @Override
    public Usuario loadUserByUsername(String email) {
        return repository.findByEmailIgnoreCase(email).orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));
    }
}
