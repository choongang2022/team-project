package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import lombok.Data;

@Data
public class LecPlanLecDto {
	private Long   lec_id;
	private String lec_name;
	private String lec_type;
	private String lec_typecode;
	private String major_gubun;
	private String lec_unit_score;
	private String lec_max_count;
	private String lec_file_path;
}
