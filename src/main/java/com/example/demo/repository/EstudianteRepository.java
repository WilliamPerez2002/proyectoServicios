package com.example.demo.repository;
import com.example.demo.model.Estudiante;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EstudianteRepository extends JpaRepository<Estudiante,String> {

    List<Estudiante> findByCedulaContaining(String cedula);
}
