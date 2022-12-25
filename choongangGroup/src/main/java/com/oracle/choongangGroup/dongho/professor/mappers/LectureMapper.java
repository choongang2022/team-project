package com.oracle.choongangGroup.dongho.professor.mappers;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.LecPlanLecDto;
import com.oracle.choongangGroup.hs.lecManagement.LectureVO;

@Mapper
public interface LectureMapper {
	@Select("SELECT * "
		  + "FROM   lecture "
		  + "WHERE  prof_name  = #{profname} "
		  + "AND    lec_status = #{status}")
	List<LectureVO> findByProfAndStatus(@Param("profname") String profName, 
										@Param("status")   String lecStatus);
	
	@Select("SELECT * "
		  + "FROM   lecture "
		  + "WHERE  prof_name    = #{profname} "
		  + "AND    lec_status   = #{lecStatus} "
		  + "AND    lec_semester = #{semester} "
		  + "AND    lec_year     = #{year}")
	List<LecPlanLecDto> findByProfNameAndYearAndSemester(@Param("profname")  String profName, 
														 @Param("year")      String year, 
														 @Param("semester")  String semester, 
														 @Param("lecStatus") String lecStatus);
	
}
