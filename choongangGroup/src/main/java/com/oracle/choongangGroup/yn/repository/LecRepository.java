package com.oracle.choongangGroup.yn.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import com.oracle.choongangGroup.sh.domain.Lecture;


public interface LecRepository  extends JpaRepository<Lecture, String>{

	List<Lecture> findByProfOrderByIdAsc(String name);
	Lecture findById(Long id);
	@Transactional
	void deleteById(Long id);
	List<Lecture> findByProfAndStatusOrderByIdAsc(String name, String string);

//	List<Lecture> searchLec(Lecture lecture);
}

	

