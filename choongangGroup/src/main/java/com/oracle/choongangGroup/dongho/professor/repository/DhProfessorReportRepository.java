package com.oracle.choongangGroup.dongho.professor.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.LectureMember;
import com.oracle.choongangGroup.sh.domain.Report;

@Repository
public interface DhProfessorReportRepository extends JpaRepository<Report, ApplicationLec> {
	// 사용하지 않는것 test용
	List<Report> findByApplicationLec_Lecture_Id(Long id);
	// 과제 성적 입력
	@Modifying(clearAutomatically = true)
	@Query("UPDATE Report r SET r.score = :score, r.grade = :grade WHERE r.id = :id")
	int updateReportScore(@Param(value = "id") Long id, @Param(value = "score") String score, @Param(value = "grade") String grade);
	
	Report findByApplicationLec_Member_Userid(String userid);

}
