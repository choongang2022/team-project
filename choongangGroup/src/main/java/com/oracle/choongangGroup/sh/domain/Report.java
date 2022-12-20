package com.oracle.choongangGroup.sh.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinColumns;
import javax.persistence.OneToOne;

import lombok.Data;
@Entity
@Data
public class Report {
	@Id
	@Column(name = "rep_id")
	@GeneratedValue
	private Long id;
	
	@OneToOne
	@JoinColumns({@JoinColumn(name = "lec_id"),
				  @JoinColumn(name = "userid") })
	private ApplicationLec applicationLec; //강의코드
	
	@Column(name = "rep_file_name")
	private String fileName; //파일명
	
	@Column(name = "rep_file_path")
	private String filePath; //파일위치
	
	@Column(name = "rep_submit_date")
	private String submitDate; //제출일
	
	@Column(name = "rep_deadline")
	private String deadline; //마감기간
	
	@Column(name = "rep_whether")
	private String whether; //제출여부
	
	@Column(name = "rep_score")
	private String score; //과제점수
	
	@Column(name = "rep_grade")
	private String grade; //등급
}