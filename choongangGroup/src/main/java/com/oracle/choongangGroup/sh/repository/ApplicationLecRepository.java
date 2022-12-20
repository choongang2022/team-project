package com.oracle.choongangGroup.sh.repository;

import java.util.List;

import org.apache.ibatis.annotations.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.oracle.choongangGroup.sh.domain.ApplicationLec;

public interface ApplicationLecRepository extends JpaRepository<ApplicationLec, Long> {
	Page<ApplicationLec> findAllByMember_UseridAndLecture_YearAndLecture_SemesterAndGubun(String userid, String year, String semester, Long gubun, Pageable pageable);
	List<ApplicationLec> findAllByMember_UseridAndLecture_YearAndLecture_SemesterAndGubun(String userid, String year, String semester, Long gubun);
	List<ApplicationLec> findByMember_Userid(String userid);
	ApplicationLec findByMember_UseridAndLecture_Id(String userid, Long lecId);
	

	
}
