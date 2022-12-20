package com.oracle.choongangGroup.dongho.professor.mappers;

import java.util.List;

import org.apache.ibatis.annotations.InsertProvider;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.UpdateProvider;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanLecDto;
import com.oracle.choongangGroup.dongho.professor.sqlprovider.LectureSql;
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
	
	@UpdateProvider(type =  LectureSql.class, method = "updateLecPlanFilePath")
	int updateLecPlanFilePath(@Param("long_lec_id")      Long   long_lec_id, 
			                  @Param("originalFileName") String originalFileName, 
			                  @Param("dBSaveFile")       String dBSaveFile);
	@SelectProvider(type = LectureSql.class, method = "findFilePathByLecId")
	String findFilePathByLecId(Long lec_id);
	
}
